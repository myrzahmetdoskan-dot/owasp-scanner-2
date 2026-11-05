# OWASP Top 10 веб-осалдық сканері

Flask + requests + BeautifulSoup + SQLite + Bootstrap + Chart.js.

## Іске қосу
```
pip install -r requirements.txt
python app.py        # http://127.0.0.1:5000
```

## Тексерулер (OWASP Top 10:2021)
| Тексеру | Санат |
|---|---|
| Қауіпсіздік тақырыптары (CSP, XFO, XCTO, HSTS, Referrer-Policy) | A05 |
| Cookie жалаулары (Secure, HttpOnly, SameSite) | A02 / A05 / A01 |
| Reflected XSS (зиянсыз маркер) | A03 |
| Error-based SQLi (бір тырнақша арқылы қате іздеу) | A03 |
| Ашық құпия файлдар, directory listing | A05 |

## Тест
Тек DVWA, OWASP Juice Shop немесе өз сайтыңызда қолданыңыз:
`docker run -p 8080:80 vulnerables/web-dvwa`, `docker run -p 3000:3000 bkimminich/juice-shop`

## Ескерту
Тек рұқсатыңыз бар жүйелерді сканерлеңіз. Сканер зиянсыз, бірақ рұқсатсыз сканерлеу заңсыз.
