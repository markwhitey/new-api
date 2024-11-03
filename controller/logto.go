package controller

import (
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/logto-io/go/client"
	"log"
	"net/http"
	"one-api/common"
	"one-api/model"
)

// 定义 Logto 的配置
func getLogtoConfig() *client.LogtoConfig {
	return &client.LogtoConfig{
		Endpoint:  common.LogtoEndpoint,
		AppId:     common.LogtoAppId,
		AppSecret: common.LogtoAppSecret,
		Scopes:    []string{"email"},
	}
}

type LogtoUser struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
}

func LogtoSignIn(c *gin.Context) {
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(
		getLogtoConfig(),
		&SessionStorage{session: session},
	)
	fmt.Println(common.LogtoEndpoint)
	signInUri, err := logtoClient.SignIn("https://aiki.cc/api/callback")
	fmt.Println("Generated signInUri:", signInUri) // 打印生成的 URL
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, signInUri)

}

func LogtoCallback(c *gin.Context) {
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(
		getLogtoConfig(),
		&SessionStorage{session: session},
	)

	err := logtoClient.HandleSignInCallback(c.Request)
	if err != nil {
		log.Printf("HandleSignInCallback failed: %v", err) // 记录错误信息
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Logto 登录失败",
		})
		return
	}

	logtoUser, err := LogtoUserInfo(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	user := model.User{
		LogtoId: logtoUser.UserID,
	}

	if model.IsLogtoIdAlreadyTaken(user.LogtoId) {
		err := user.FillUserByLogtoId()
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": err.Error(),
			})
			return
		}
		if user.Id == 0 {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "用户已注销",
			})
			return
		}
	} else {
		if common.RegisterEnabled {
			user.Username = logtoUser.Email
			user.DisplayName = "Logto User"
			user.Email = logtoUser.Email
			user.Role = common.RoleCommonUser
			user.Status = common.UserStatusEnabled
			user.LogtoId = logtoUser.UserID

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

	c.Redirect(http.StatusTemporaryRedirect, "/login-success") // 前端处理登录成功的页面

}

func LogtoUserStatus(c *gin.Context) {
	// 获取 Logto 用户信息
	logtoUser, err := LogtoUserInfo(c)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"logged_in": false,
			"message":   "用户未登录",
		})
		return
	}

	// 根据 LogtoId 查找或创建用户
	user := model.User{
		LogtoId: logtoUser.UserID,
	}
	err = user.FillUserByLogtoId()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"logged_in": false,
			"message":   "获取用户信息失败",
		})
		return
	}

	if user.Id == 0 {
		c.JSON(http.StatusOK, gin.H{
			"logged_in": false,
			"message":   "用户未注册",
		})
		return
	}

	// 设置会话并返回用户信息
	setupLogin(&user, c)

}

func LogtoUserInfo(c *gin.Context) (*LogtoUser, error) {
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(getLogtoConfig(), &SessionStorage{session: session})

	if !logtoClient.IsAuthenticated() {
		return nil, fmt.Errorf("unauthorized: user not authenticated")
	}

	userInfo, err := logtoClient.FetchUserInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}

	logtoUser := &LogtoUser{
		UserID: userInfo.Sub,
		Email:  userInfo.Email,
	}

	return logtoUser, nil
}

func LogtoSignOut(c *gin.Context) {
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(
		getLogtoConfig(),
		&SessionStorage{session: session},
	)

	signOutUri, signOutErr := logtoClient.SignOut("/")

	if signOutErr != nil {
		c.String(http.StatusOK, signOutErr.Error())
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, signOutUri)
}
