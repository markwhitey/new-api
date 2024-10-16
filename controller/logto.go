package controller

import (
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/logto-io/go/client"
	"net/http"
	"one-api/common"
	"one-api/model"
	"strconv"
)

// 定义 Logto 的配置
var logtoConfig = &client.LogtoConfig{
	Endpoint:  common.LogtoEndpoint,
	AppId:     common.LogtoAppId,
	AppSecret: common.LogtoAppSecret,
	Scopes:    []string{"email"},
}

type LogtoUser struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
}

func LogtoOAuth(c *gin.Context) {
	session := sessions.Default(c)
	state := c.Query("state")
	if state == "" || session.Get("oauth_state") == nil || state != session.Get("oauth_state").(string) {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "state is empty or not same",
		})
		return
	}
	username := session.Get("username")
	if username != nil {
		LogtoBind(c)
		return
	}

	if !common.LogtoOAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "管理员未开启通过 Logto 登录以及注册",
		})
		return
	}
	code := c.Query("code")
	githubUser, err := getGitHubUserInfoByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	user := model.User{
		LogtoId: githubUser.Login,
	}
	// IsGitHubIdAlreadyTaken is unscoped
	if model.IsLogtoIdAlreadyTaken(user.GitHubId) {
		// FillUserByGitHubId is scoped
		err := user.FillUserByLogtoId()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
		// if user.Id == 0 , user has been deleted
		if user.Id == 0 {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "用户已注销",
			})
			return
		}
	} else {
		if common.RegisterEnabled {
			user.Username = "logto_" + strconv.Itoa(model.GetMaxUserId()+1)
			if githubUser.Name != "" {
				user.DisplayName = githubUser.Name
			} else {
				user.DisplayName = "GitHub User"
			}
			user.Email = githubUser.Email
			user.Role = common.RoleCommonUser
			user.Status = common.UserStatusEnabled

			if err := user.Insert(0); err != nil {
				c.JSON(http.StatusOK, gin.H{
					"success": false,
					"message": err.Error(),
				})
				return
			}
		} else {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "管理员关闭了新用户注册",
			})
			return
		}
	}

	if user.Status != common.UserStatusEnabled {
		c.JSON(http.StatusOK, gin.H{
			"message": "用户已被封禁",
			"success": false,
		})
		return
	}
	setupLogin(&user, c)
}

func LogtoBind(c *gin.Context) {
	if !common.LogtoOAuthEnabled {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "管理员未开启通过 Logto 登录以及注册",
		})
		return
	}

	code := c.Query("code")
	githubUser, err := getGitHubUserInfoByCode(code)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	user := model.User{
		GitHubId: githubUser.Login,
	}

	if model.IsLogtoIdAlreadyTaken(user.GitHubId) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "该 Logto 账户已被绑定",
		})
		return
	}

	session := sessions.Default(c)
	id := session.Get("id")
	// id := c.GetInt("id")  // critical bug!
	user.Id = id.(int)

	err = user.FillUserById()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	// 调用 LogtoUserInfo 获取用户信息并处理错误
	logtoUser, err := LogtoUserInfo(c)
	if err != nil {
		// 如果获取 Logto 用户信息失败，返回错误响应
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	// 这里将 logtoUser.UserID 赋值给 user.LogtoId
	user.LogtoId = logtoUser.UserID

	err = user.Update(false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "bind",
	})
}

func LogtoSignIn(c *gin.Context) {
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(
		logtoConfig,
		&SessionStorage{session: session},
	)

	signInUri, err := logtoClient.SignIn("<your-redirect-uri>")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, signInUri)
}

func LogtoCallback(c *gin.Context) {
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(
		logtoConfig,
		&SessionStorage{session: session},
	)

	// The sign-in callback request is handled by Logto
	err := logtoClient.HandleSignInCallback(c.Request)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, "/")
}

func LogtoUserInfo(c *gin.Context) (*LogtoUser, error) {
	// 获取 session 并创建 logtoClient
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(logtoConfig, &SessionStorage{session: session})

	// 检查是否已经登录认证
	if !logtoClient.IsAuthenticated() {
		return nil, fmt.Errorf("unauthorized: user not authenticated")
	}

	// 获取用户信息
	userInfo, err := logtoClient.FetchUserInfo()
	if err != nil {
		// 如果获取用户信息失败，返回错误
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}

	// 构造 LogtoUser 对象
	logtoUser := &LogtoUser{
		UserID: userInfo.Sub,
		Email:  userInfo.Email,
	}

	// 返回用户信息而不是直接返回给客户端
	return logtoUser, nil
}

func LogtoSignOut(c *gin.Context) {
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(
		logtoConfig,
		&SessionStorage{session: session},
	)

	// The sign-out request is handled by Logto.
	// The user will be redirected to the Post Sign-out Redirect URI on signed out.
	signOutUri, signOutErr := logtoClient.SignOut("<your-post-sign-out-uri>")

	if signOutErr != nil {
		c.String(http.StatusOK, signOutErr.Error())
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, signOutUri)
}
