package main

import (
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"io"

	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	_ "github.com/glebarez/sqlite"
)

// 数据存储结构体
type ShortURL struct {
	ID        int       `db:"id"`
	ShortCode string    `db:"short_code"`
	URL       string    `db:"url"`
	CreatedAt time.Time `db:"created_at"`
}

type User struct {
	ID       int    `db:"id"`
	Username string `db:"username"`
	Password string `db:"password"`
}

// 内存存储器
type DbStore struct {
	db *sql.DB // SQLite数据库连接
}

func openDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "./urls.sqlite")
	if err != nil {
		return nil, err
	}

	// 初始化数据库表
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS short_urls (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		short_code TEXT UNIQUE NOT NULL,
		url TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS api_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token TEXT UNIQUE NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (store *DbStore) Close() {
	if store.db != nil {
		store.db.Close()
	}
}

func (store *DbStore) CreateShortURL(url, customCode string) (string, error) {
	// 验证URL格式是否正确
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "", fmt.Errorf("无效的URL")
	}

	// 验证自定义短码格式
	if customCode != "" {
		if len(customCode) < 1 || len(customCode) > 10 {
			return "", fmt.Errorf("自定义短码长度应在1到10个字符之间")
		}
		var count int
		err := store.db.QueryRow("SELECT COUNT(*) FROM short_urls WHERE short_code = ?", customCode).Scan(&count)
		if err != nil {
			return "", fmt.Errorf("数据库查询失败")
		}
		if count > 0 {
			return "", fmt.Errorf("自定义短码已被使用")
		}
	} else {
		customCode = generateShortCode()
	}

	_, err := store.db.Exec("INSERT INTO short_urls(short_code, url) VALUES (?, ?)", customCode, url)
	if err != nil {
		return "", fmt.Errorf("数据库插入失败")
	}

	return customCode, nil
}

func generateShortCode() string {
	hash := md5.New()
	io.WriteString(hash, time.Now().String())
	sum := hash.Sum(nil)
	return fmt.Sprintf("%x", sum)[:6]
}

func (store *DbStore) GetShortURL(shortCode string) (string, error) {
	var url string
	err := store.db.QueryRow("SELECT url FROM short_urls WHERE short_code = ?", shortCode).Scan(&url)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("短网址不存在")
		}
		return "", fmt.Errorf("数据库查询失败")
	}
	return url, nil
}

func (store *DbStore) DeleteURL(shortCode string) error {
	result, err := store.db.Exec("DELETE FROM short_urls WHERE short_code = ?", shortCode)
	if err != nil {
		return fmt.Errorf("数据库删除失败")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("获取受影响行数失败")
	}
	if rowsAffected == 0 {
		return fmt.Errorf("短网址不存在或未删除")
	}

	return nil
}

func (store *DbStore) UpdateURL(shortCode, newURL string) error {
	if !strings.HasPrefix(newURL, "http://") && !strings.HasPrefix(newURL, "https://") {
		return fmt.Errorf("无效的URL")
	}

	result, err := store.db.Exec("UPDATE short_urls SET url = ? WHERE short_code = ?", newURL, shortCode)
	if err != nil {
		return fmt.Errorf("数据库更新失败")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("获取受影响行数失败")
	}
	if rowsAffected == 0 {
		return fmt.Errorf("短网址不存在或未更新")
	}

	return nil
}

func generateAPIToken(length int) (string, error) {
	tokenBytes := make([]byte, length)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

func getAPIToken(store *DbStore) (string, error) {
	var token string
	err := store.db.QueryRow("SELECT token FROM api_tokens LIMIT 1").Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			newToken, err := generateAPIToken(32)
			if err != nil {
				return "", err
			}
			_, err = store.db.Exec("INSERT INTO api_tokens(token) VALUES (?)", newToken)
			if err != nil {
				return "", err
			}
			return newToken, nil
		}
		return "", err
	}
	return token, nil
}

func main() {
	// 命令行参数解析
	portPtr := flag.Int("port", 8080, "服务器端口")
	printTokenPtr := flag.Bool("print-token", false, "打印生成的API Token")

	// 用户管理
	addUserPtr := flag.Bool("add-user", false, "添加用户")
	delUserPtr := flag.Bool("del-user", false, "删除用户")
	usernamePtr := flag.String("username", "", "用户名")
	passwordPtr := flag.String("password", "", "密码")
	flag.Parse()

	// 初始化SQLite数据库
	db, err := openDatabase()
	if err != nil {
		log.Fatal("无法连接到数据库:", err)
	}
	defer db.Close()

	store := &DbStore{
		db: db,
	}

	// 管理用户
	if *addUserPtr || *delUserPtr {
		if *addUserPtr {
			// 添加用户
			if *usernamePtr == "" || *passwordPtr == "" {
				log.Fatal("请提供用户名和密码")
			}
			hashedPassword := sha256.Sum256([]byte(*passwordPtr))
			_, err := store.db.Exec("INSERT INTO users(username, password) VALUES (?, ?)", *usernamePtr, hex.EncodeToString(hashedPassword[:]))
			if err != nil {
				log.Fatal("无法添加用户:", err)
			}
			log.Printf("用户 [%s] 添加成功", *usernamePtr)
			os.Exit(0)
		} else if *delUserPtr {
			// 删除用户
			if *usernamePtr == "" {
				log.Fatal("请提供用户名")
			}
			_, err := store.db.Exec("DELETE FROM users WHERE username = ?", *usernamePtr)
			if err != nil {
				log.Fatal("无法删除用户:", err)
			}
			log.Printf("用户 [%s] 删除成功", *usernamePtr)
			os.Exit(0)
		}
	}

	// 获取API Token
	apiToken, err := getAPIToken(store)
	if err != nil {
		log.Fatalf("无法获取API Token: %v", err)
	}

	// 如果需要打印Token
	if *printTokenPtr {
		fmt.Printf("生成的API Token: %s\n", apiToken)
		os.Exit(0)
	}

	// 定义HTML模板
	tmpl := template.Must(template.New("web").Parse(`
	<html>
	<head>
		<title>短网址服务</title>
		<style>
			body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
			h1 { text-align: center; color: #333; }
			form { margin: 20px 0; }
			label { display: block; margin-top: 10px; }
			input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin-top: 5px; }
			input[type="submit"] { padding: 10px 20px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
			.error { color: red; }
			.button-container { display: flex; justify-content: space-between; }
		</style>
	</head>
	<body>
		<h1>短网址服务</h1>
		{{if .IsLoggedIn}}
			<h2>生成短网址</h2>
			<form>
				<label>网址: <input type="text" name="url"></label>
				<label>自定义短码: <input type="text" name="custom_code"></label>
				<input type="hidden" name="token" value="{{.APIToken}}">
				<br>
				<div class="button-container">
					<button type="button" onclick="generateShortURL()">生成短网址</button>
					<button type="button" onclick="queryShortURL()">查询短网址</button>
					<button type="button" onclick="deleteShortURL()">删除短网址</button>
					<button type="button" onclick="updateLongURL()">更新长网址</button>
				</div>
			</form>
			<a href="/logout">退出登录</a>
		{{else}}
			<h2>登录</h2>
			<form method="POST" action="/htm">
				<label>用户名: <input type="text" name="username" value="{{.Username}}"></label>
				<label>密码: <input type="password" name="password" value="{{.Password}}"></label>
				<input type="submit" value="登录">
			</form>
		{{end}}
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		<script>
			function generateShortURL() {
				const longURL = document.querySelector('input[name="url"]').value;
				const shortCode = document.querySelector('input[name="custom_code"]').value;
				fetch('/api/generate', {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams({ url: longURL , custom_code: shortCode })
				}).then(response => response.json()).then(data => alert(JSON.stringify(data)));
			}

			function queryShortURL() {
				const shortCode = document.querySelector('input[name="custom_code"]').value;
				fetch('/api/query', {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams({ short_code: shortCode })
				}).then(response => response.json()).then(data => alert(JSON.stringify(data)));
			}

			function deleteShortURL() {
				const shortCode = document.querySelector('input[name="custom_code"]').value;
				fetch('/api/delete', {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams({ short_code: shortCode })
				}).then(response => response.text()).then(data => alert(data));
			}

			function updateLongURL() {
				const shortCode = document.querySelector('input[name="custom_code"]').value;
				const newURL = prompt("请输入新的长网址:");
				if (newURL) {
					fetch('/api/update', {
						method: 'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: new URLSearchParams({ short_code: shortCode, new_url: newURL })
					}).then(response => response.text()).then(data => alert(data));
				}
			}
		</script>
	</body>
	</html>
	`))

	// 处理HTML页面，包含用户名和密码验证
	http.HandleFunc("/htm", func(w http.ResponseWriter, r *http.Request) {
		type FormData struct {
			IsLoggedIn bool
			APIToken   string
			Username   string
			Password   string
			Error      string
		}
		formData := FormData{
			APIToken: apiToken,
		}

		// 从Cookie中获取Token
		sessionToken := ""
		cookie, err := r.Cookie("session_token")
		if err == nil {
			sessionToken = cookie.Value
		}

		// 检查Token是否有效
		if sessionToken == apiToken {
			formData.IsLoggedIn = true
		}

		if r.Method == "GET" {
			tmpl.Execute(w, formData)
		} else if r.Method == "POST" {
			// 登录逻辑
			if !formData.IsLoggedIn {
				username := r.FormValue("username")
				password := r.FormValue("password")

				var hashedPassword string
				err := store.db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
				if err != nil {
					if err == sql.ErrNoRows {
						formData.Error = "用户不存在"
						tmpl.Execute(w, formData)
						return
					}
					http.Error(w, "数据库查询失败", http.StatusInternalServerError)
					return
				}

				// 验证密码
				inputHash := sha256.Sum256([]byte(password))
				if hex.EncodeToString(inputHash[:]) != hashedPassword {
					formData.Error = "密码错误"
					tmpl.Execute(w, formData)
					return
				}

				// 设置Cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "session_token",
					Value:    apiToken,
					Path:     "/",
					HttpOnly: true,
					MaxAge:   3600, // 有效期1小时
				})

				formData.IsLoggedIn = true
				tmpl.Execute(w, formData)
			}
		}
	})

	// 处理解析短网址的请求
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			http.Error(w, "无效的路径，请访问 /htm 查看主页", http.StatusBadRequest)
			return
		}

		shortCode := strings.TrimPrefix(path, "/")
		url, err := store.GetShortURL(shortCode)
		if err == nil {
			http.Redirect(w, r, url, http.StatusFound)
		} else {
			http.NotFound(w, r)
		}
	})

	// 处理API请求（生成短网址）
	http.HandleFunc("/api/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			url := r.FormValue("url")
			customCode := r.FormValue("custom_code")

			if url == "" {
				http.Error(w, "请输入网址", http.StatusBadRequest)
				return
			}

			shortCode, err := store.CreateShortURL(url, customCode)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"short_url": "%s/%s"}`, fmt.Sprintf("http://localhost:%d", *portPtr), shortCode)
		}
	})

	// 处理API请求（查询短网址）
	http.HandleFunc("/api/query", func(w http.ResponseWriter, r *http.Request) {
		shortCode := r.FormValue("short_code")

		if shortCode == "" {
			http.Error(w, "需要提供短码参数", http.StatusBadRequest)
			return
		}

		url, err := store.GetShortURL(shortCode)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"short_code": "%s", "url": "%s"}`, shortCode, url)
	})

	// 处理API请求（删除短网址）
	http.HandleFunc("/api/delete", func(w http.ResponseWriter, r *http.Request) {
		shortCode := r.FormValue("short_code")

		if shortCode == "" {
			http.Error(w, "需要提供短码参数", http.StatusBadRequest)
			return
		}

		err := store.DeleteURL(shortCode)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "删除成功")
	})

	// 处理API请求（更新长网址）
	http.HandleFunc("/api/update", func(w http.ResponseWriter, r *http.Request) {
		shortCode := r.FormValue("short_code")
		newUrl := r.FormValue("new_url")

		if shortCode == "" || newUrl == "" {
			http.Error(w, "需要提供短码和新网址参数", http.StatusBadRequest)
			return
		}

		err := store.UpdateURL(shortCode, newUrl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "更新成功")
	})

	// 退出登录
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "session_token",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		http.Redirect(w, r, "/htm", http.StatusSeeOther)
	})

	log.Printf("服务器启动于: http://localhost:%d", *portPtr)
	log.Printf("API Token: %s", apiToken)
	err = http.ListenAndServe(fmt.Sprintf(":%d", *portPtr), nil)
	if err != nil {
		log.Fatal("无法启动服务器:", err)
	}
}