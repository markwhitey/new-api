package controller

import (
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/logto-io/go/client"
	"net/http"
	"one-api/common"
	"one-api/model"
)

// 定义 Logto 的配置
var logtoConfig = &client.LogtoConfig{
	Endpoint:  "https://login.aiki.cc/",
	AppId:     "pweleqg56ilp5qbs49e77",
	AppSecret: "lb9619t5cmhwfX4QfMed3VBuh14xjC86",
	Scopes:    []string{"email"},
}

type LogtoUser struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
}

func LogtoSignIn(c *gin.Context) {
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(
		logtoConfig,
		&SessionStorage{session: session},
	)
	fmt.Println(common.LogtoEndpoint) // 打印生成的 URL
	signInUri, err := logtoClient.SignIn("http://localhost:3000/api/callback")
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
		logtoConfig,
		&SessionStorage{session: session},
	)

	err := logtoClient.HandleSignInCallback(c.Request)
	if err != nil {
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
			user.Username = "Logto User" + logtoUser.UserID
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

	// 设置会话
	setupLogin(&user, c)

	// 返回 JSON 响应，通知前端登录成功
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "登录成功",
		"data":    user, // 返回用户数据给前端
	})
}

func LogtoUserInfo(c *gin.Context) (*LogtoUser, error) {
	session := sessions.Default(c)
	logtoClient := client.NewLogtoClient(logtoConfig, &SessionStorage{session: session})

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
		logtoConfig,
		&SessionStorage{session: session},
	)

	signOutUri, signOutErr := logtoClient.SignOut("/")

	if signOutErr != nil {
		c.String(http.StatusOK, signOutErr.Error())
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, signOutUri)
}
