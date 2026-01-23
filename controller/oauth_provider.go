package controller

import (
	"net/http"
	"slices"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service/hydra"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// OAuthProviderController handles Hydra login/consent/logout flows
type OAuthProviderController struct {
	hydra hydra.Provider
}

// NewOAuthProviderController creates a new OAuth provider controller
func NewOAuthProviderController(hydraProvider hydra.Provider) *OAuthProviderController {
	return &OAuthProviderController{
		hydra: hydraProvider,
	}
}

// OAuthLoginRequest represents the login form submission
type OAuthLoginRequest struct {
	Challenge string `json:"challenge" form:"challenge"`
	Username  string `json:"username" form:"username"`
	Password  string `json:"password" form:"password"`
}

// OAuthLogin handles GET /oauth/login - displays login page or auto-accepts if session exists
func (ctrl *OAuthProviderController) OAuthLogin(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "missing login_challenge",
		})
		return
	}

	// Get login request from Hydra
	loginReq, err := ctrl.hydra.GetLoginRequest(c.Request.Context(), challenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "invalid login challenge: " + err.Error(),
		})
		return
	}

	// If skip is true, the user has already authenticated with Hydra
	// We can accept the login request immediately
	if loginReq.GetSkip() {
		redirect, err := ctrl.hydra.AcceptLogin(c.Request.Context(), challenge, loginReq.GetSubject(), false, 0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "failed to accept login: " + err.Error(),
			})
			return
		}
		c.Redirect(http.StatusFound, redirect.RedirectTo)
		return
	}

	// Check if user is already logged in via session
	session := sessions.Default(c)
	if userID := session.Get("id"); userID != nil {
		subject := strconv.Itoa(userID.(int))
		redirect, err := ctrl.hydra.AcceptLogin(c.Request.Context(), challenge, subject, true, common.HydraLoginRememberFor)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "failed to accept login: " + err.Error(),
			})
			return
		}
		c.Redirect(http.StatusFound, redirect.RedirectTo)
		return
	}

	// Return login page info for frontend to render
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"challenge":       challenge,
			"client_id":       loginReq.Client.GetClientId(),
			"client_name":     loginReq.Client.GetClientName(),
			"requested_scope": loginReq.GetRequestedScope(),
		},
	})
}

// OAuthLoginSubmit handles POST /oauth/login - processes login form
func (ctrl *OAuthProviderController) OAuthLoginSubmit(c *gin.Context) {
	var req OAuthLoginRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "invalid request: " + err.Error(),
		})
		return
	}

	if req.Challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "missing challenge",
		})
		return
	}

	if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "missing username or password",
		})
		return
	}

	// Check if password login is enabled
	if !common.PasswordLoginEnabled {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "password login is disabled",
		})
		return
	}

	// Validate user credentials using existing model
	user := model.User{
		Username: req.Username,
		Password: req.Password,
	}
	if err := user.ValidateAndFill(); err != nil {
		// Reject login with error
		redirect, rejectErr := ctrl.hydra.RejectLogin(c.Request.Context(), req.Challenge, "access_denied", err.Error())
		if rejectErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "failed to reject login: " + rejectErr.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success":     false,
			"message":     err.Error(),
			"redirect_to": redirect.RedirectTo,
		})
		return
	}

	// Check if 2FA is enabled
	if model.IsTwoFAEnabled(user.Id) {
		// Store pending state for 2FA
		session := sessions.Default(c)
		session.Set("oauth_pending_user_id", user.Id)
		session.Set("oauth_pending_challenge", req.Challenge)
		if err := session.Save(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "failed to save session",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"require_2fa": true,
				"challenge":   req.Challenge,
			},
		})
		return
	}

	// Accept login
	subject := strconv.Itoa(user.Id)
	redirect, err := ctrl.hydra.AcceptLogin(c.Request.Context(), req.Challenge, subject, true, common.HydraLoginRememberFor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "failed to accept login: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"redirect_to": redirect.RedirectTo,
	})
}

// OAuthLogin2FA handles POST /oauth/login/2fa - processes 2FA verification for OAuth login
func (ctrl *OAuthProviderController) OAuthLogin2FA(c *gin.Context) {
	var req struct {
		Code string `json:"code" form:"code"`
	}
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "invalid request",
		})
		return
	}

	session := sessions.Default(c)
	userID := session.Get("oauth_pending_user_id")
	challenge := session.Get("oauth_pending_challenge")

	if userID == nil || challenge == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "no pending 2FA verification",
		})
		return
	}

	// Verify 2FA code using existing logic
	twoFA, err := model.GetTwoFAByUserId(userID.(int))
	if err != nil || twoFA == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "2FA not configured",
		})
		return
	}

	// Check if locked
	if twoFA.IsLocked() {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"success": false,
			"message": "too many failed attempts, please try again later",
		})
		return
	}

	// Verify TOTP code
	valid := common.ValidateTOTPCode(twoFA.Secret, req.Code)
	if !valid {
		// Try backup code
		valid = model.UseBackupCode(userID.(int), req.Code)
	}

	if !valid {
		_ = twoFA.IncrementFailedAttempts()
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "invalid verification code",
		})
		return
	}

	// Clear pending state
	session.Delete("oauth_pending_user_id")
	session.Delete("oauth_pending_challenge")
	_ = session.Save()

	// Accept login
	subject := strconv.Itoa(userID.(int))
	redirect, err := ctrl.hydra.AcceptLogin(c.Request.Context(), challenge.(string), subject, true, common.HydraLoginRememberFor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "failed to accept login: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"redirect_to": redirect.RedirectTo,
	})
}

// OAuthConsent handles GET /oauth/consent - displays consent page
func (ctrl *OAuthProviderController) OAuthConsent(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "missing consent_challenge",
		})
		return
	}

	consentReq, err := ctrl.hydra.GetConsentRequest(c.Request.Context(), challenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "invalid consent challenge: " + err.Error(),
		})
		return
	}

	// If skip is true, the user has already given consent
	if consentReq.GetSkip() {
		redirect, err := ctrl.hydra.AcceptConsent(
			c.Request.Context(),
			challenge,
			consentReq.GetRequestedScope(),
			false,
			0,
			nil,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "failed to accept consent: " + err.Error(),
			})
			return
		}
		c.Redirect(http.StatusFound, redirect.RedirectTo)
		return
	}

	// Check if this is a trusted first-party client (auto-consent)
	clientID := consentReq.Client.GetClientId()
	if isTrustedOAuthClient(clientID) {
		redirect, err := ctrl.hydra.AcceptConsent(
			c.Request.Context(),
			challenge,
			consentReq.GetRequestedScope(),
			true,
			common.HydraConsentRememberFor,
			nil,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "failed to accept consent: " + err.Error(),
			})
			return
		}
		c.Redirect(http.StatusFound, redirect.RedirectTo)
		return
	}

	// Return consent page info for frontend
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"challenge":       challenge,
			"client_id":       clientID,
			"client_name":     consentReq.Client.GetClientName(),
			"requested_scope": consentReq.GetRequestedScope(),
			"subject":         consentReq.GetSubject(),
		},
	})
}

// OAuthConsentRequest represents consent form submission
type OAuthConsentRequest struct {
	Challenge  string   `json:"challenge" form:"challenge"`
	GrantScope []string `json:"grant_scope" form:"grant_scope"`
	Remember   bool     `json:"remember" form:"remember"`
}

// OAuthConsentSubmit handles POST /oauth/consent - processes consent form
func (ctrl *OAuthProviderController) OAuthConsentSubmit(c *gin.Context) {
	var req OAuthConsentRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "invalid request: " + err.Error(),
		})
		return
	}

	if req.Challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "missing challenge",
		})
		return
	}

	var rememberFor int64 = 0
	if req.Remember {
		rememberFor = common.HydraConsentRememberFor
	}

	redirect, err := ctrl.hydra.AcceptConsent(
		c.Request.Context(),
		req.Challenge,
		req.GrantScope,
		req.Remember,
		rememberFor,
		nil,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "failed to accept consent: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"redirect_to": redirect.RedirectTo,
	})
}

// OAuthConsentReject handles POST /oauth/consent/reject - rejects consent
func (ctrl *OAuthProviderController) OAuthConsentReject(c *gin.Context) {
	challenge := c.PostForm("challenge")
	if challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "missing challenge",
		})
		return
	}

	redirect, err := ctrl.hydra.RejectConsent(c.Request.Context(), challenge, "access_denied", "user denied consent")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "failed to reject consent: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"redirect_to": redirect.RedirectTo,
	})
}

// OAuthLogout handles GET /oauth/logout - displays logout confirmation
func (ctrl *OAuthProviderController) OAuthLogout(c *gin.Context) {
	challenge := c.Query("logout_challenge")
	if challenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "missing logout_challenge",
		})
		return
	}

	// Validate the logout challenge exists
	_, err := ctrl.hydra.GetLogoutRequest(c.Request.Context(), challenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "invalid logout challenge: " + err.Error(),
		})
		return
	}

	// Auto-accept logout for now
	// Could show a confirmation page if needed
	redirect, err := ctrl.hydra.AcceptLogout(c.Request.Context(), challenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "failed to accept logout: " + err.Error(),
		})
		return
	}

	// Clear local session
	session := sessions.Default(c)
	session.Clear()
	_ = session.Save()

	c.Redirect(http.StatusFound, redirect.RedirectTo)
}

// isTrustedOAuthClient checks if a client is a trusted first-party app
// Trusted clients get auto-consent without user interaction
// Configure via HydraTrustedClients setting (comma-separated client IDs)
func isTrustedOAuthClient(clientID string) bool {
	return slices.Contains(common.HydraTrustedClients, clientID)
}
