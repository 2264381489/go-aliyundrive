/**
 * Copyright 2022 chyroc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package aliyundrive

import (
	"encoding/hex"
	"fmt"
	"github.com/tickstep/library-go/crypto"
	"github.com/tickstep/library-go/crypto/secp256k1"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/chyroc/gorequests"

	"github.com/chyroc/go-aliyundrive/internal/helper_config"
)

type AliyunDrive struct {
	// logger
	logger   Logger
	logLevel LogLevel

	// config
	workDir string // defalut: ~/.go-aliyundrive-sdk
	store   Store

	// session
	session *gorequests.Session

	AppConfig *AppConfig

	// service
	ShareLink *ShareLinkService
	Auth      *AuthService
	File      *FileService
}

func newClient(options []ClientOptionFunc) *AliyunDrive {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("get HOME failed: %s", err))
	}

	r := &AliyunDrive{
		// logger
		logLevel: LogLevelTrace,

		// timeout:      time.Second * 3,
		session: gorequests.NewSession(helper_config.CookieFile),

		// config
		workDir: home + "/.go-aliyundrive-sdk",

		AppConfig: InitDefaultAppConfig(),
	}
	for _, v := range options {
		if v != nil {
			v(r)
		}
	}

	_ = os.MkdirAll(r.workDir, 0o777)
	r.initService()

	if r.logger == nil {
		r.logger = r.newDefaultLogger()
	}
	if r.store == nil {
		r.store = NewFileStore(r.workDir + "/token.json")
	}

	return r
}

func (r *AliyunDrive) initService() {
	r.ShareLink = &ShareLinkService{cli: r}
	r.Auth = &AuthService{cli: r}
	r.File = &FileService{cli: r}
}

func InitDefaultAppConfig() *AppConfig {
	return &AppConfig{
		AppId:         DefaultAppId,
		DeviceId:      RandomDeviceId(),
		UserId:        "",
		PublicKey:     "",
		SignatureData: "",
	}
}

// AppConfig 存储客户端相关配置参数，目前主要是签名需要用的参数
type AppConfig struct {
	AppId string `json:"appId"`
	// DeviceId标识登录客户端，阿里限制：为了保障你的数据隐私安全，阿里云盘最多只允许你同时登录 10 台设备。你已超出最大设备数量，请先选择一台设备下线，才可以继续使用
	DeviceId      string `json:"deviceId"`
	UserId        string `json:"userId"`
	Nonce         int32  `json:"nonce"`
	PublicKey     string `json:"publicKey"`
	SignatureData string `json:"signatureData"`

	PrivKey *secp256k1.PrivKey `json:"-"`
	PubKey  *crypto.PubKey     `json:"-"`
}

const (
	// DefaultDeviceName 默认客户端名称
	DefaultDeviceName = "Chrome浏览器"

	// DefaultClientId 默认的clientId
	DefaultClientId = "cf9f70e8fc61430f8ec5ab5cadf31375"
	// DefaultAppId
	DefaultAppId = "25dzX3vbYqktVxyX"
)

// RandomDeviceId 随机生成device-id
func RandomDeviceId() string {
	count := 24
	STR_SET := "abcdefjhijklmnopqrstuvwxyzABCDEFJHIJKLMNOPQRSTUVWXYZ1234567890"
	rand.Seed(time.Now().UnixNano())
	str := strings.Builder{}
	for i := 0; i < count; i++ {
		str.WriteByte(byte(STR_SET[rand.Intn(len(STR_SET))]))
	}
	return str.String()
}

func randInt(min int, max int) int {
	return min + rand.Intn(max-min)
}

func randomString(l int) []byte {
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		rand.NewSource(time.Now().UnixNano())
		bytes[i] = byte(randInt(1, 2^256-1))
	}
	return bytes
}

func (r *AliyunDrive) calcSignature() error {
	max := 32
	key := randomString(max)
	r.AppConfig.Nonce = 0
	data := fmt.Sprintf("%s:%s:%s:%d", r.AppConfig.AppId, r.AppConfig.DeviceId, r.AppConfig.UserId, r.AppConfig.Nonce)
	var privKey = secp256k1.PrivKey(key)
	r.AppConfig.PrivKey = &privKey
	pubKey := privKey.PubKey()
	r.AppConfig.PubKey = &pubKey
	r.AppConfig.PublicKey = "04" + hex.EncodeToString(pubKey.Bytes())
	signature, err := privKey.Sign([]byte(data))
	if err != nil {
		return err
	}
	r.AppConfig.SignatureData = hex.EncodeToString(signature) + "01"
	return nil
}
