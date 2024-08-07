---
icon: material/web
tags:
  - وب
  - نقطه شروع وب
---
# وب

## وقتی می‌گیم چلنج یا چالش وب, دقیقا از چی صحبت می‌کنیم؟

دسته‌بندی وب, یکی از رایج‌ترین, یا بهتره بگیم رایج‌ترین دسته در مسابقات فتح پرچم هست که هدف‌ از این دسته پیدا کردن و اکسپلویت کردن آسیب پذیری‌های اپلیکیشن‌های تحت وب و در نهایت رسیدن به فلگ و دریافت امتیاز اون چلنج هست.  
بازی کردن و حل کردن این نوع چالش‌ها می‌تونه شما رو با ابزار‌ها, بایپس‌ها و متد‌های مختلف آشنا کنه و در کنارش بهتون سورس کد خوانی در زبان‌های برنامه نویسی مختلف رو یاد بده که در کل این‌ها می‌تونن خیلی برای ارتقا دانش وب هکینگ شما در اپلیکیشن‌های واقعی مفید باشند (دیدم که می‌گم. به شرط اینکه با سناریو‌های realworld هم آشنا باشید); پس اگر احیانا بهتون گفتند که این‌ها فقط بازی هستند و توی دنیای واقعی کاربردی ندارند, باور نکنید.

&nbsp;

## دانش مورد نیاز برای شروع این حوزه چیه؟

**درک ساختار وب:** تا بحال به این فکر کردید که مرورگر چطوری یک وبسایت رو [render](https://blog.logrocket.com/how-browser-rendering-works-behind-scenes/ "How browser rendering works?") می‌کنه؟ صفحه‌ای که به شما نشون داده می‌شه متشکل از [HTML](https://www.w3schools.com/html/ "HTML Tutorial"), [CSS](https://www.w3schools.com/w3css/ "CSS Tutorial") و [Javascript](https://www.w3schools.com/js/ "Ctrl-click to open: Javascript Tutorial") هست, لذا لازمه که تا حدودی باهاشون آشنا باشید (CSS مهم نیست و بخش اصلی HTML و Javascript هست.). هرچقدر بیشتر Javascript بلد باشید به مرور متوجه می‌شید که چقدر می‌تونه کمک‌تون بکنه. توجه داشته باشید که شما نمی‌خواید یک طراح حرفه‌ای وبسایت بشید, در نتیجه تا حدی یاد بگیرید که کارتون رو راه بندازه و بعد هروقت لازم شد, دوباره برگردید و چیز‌هایی رو که نیاز هست یاد بگیرید.

**درک پروتکل HTTP:** برای ورود به این حوزه باید حتما باید یک درک حداقلی از پروتکل [HTTP](https://www.tutorialspoint.com/http "HTTP Tutorial") داشته باشید چون تمام وب بر روی همین پروتکل سوار هست و تا ندونید که چطوری کار می‌کنه سردرگرم خواهید بود.

**درک برنامه نویسی:** از اونجایی که خیلی از چلنج‌ها حاوی سورس کد هستند, باید توانایی خواندن سورس کد و درک اون رو داشته باشید. پس خیلی خوبه که حداقل با یکی از زبان‌های برنامه نویسی تحت وب آشنایی داشته باشید. فرض کنید یک چلنج طراحی شده که حاوی کد Node.js هست, دقت کنید که مهم اینه که بتونید این کد رو درک کنید و پی ببرید که داره چکار می‌کنه, و لزومی نداره که بتونید با این زبان یک وبسایت بنویسید. باز‌ هم تاکید می‌کنم که شما نمی‌خواید یک طراح وبسایت بشید.

**درک حداقلی از [آسیب پذیری‌](https://fa.wikipedia.org/wiki/%D8%A2%D8%B3%DB%8C%D8%A8%E2%80%8C%D9%BE%D8%B0%DB%8C%D8%B1%DB%8C_%28%D8%B1%D8%A7%DB%8C%D8%A7%D9%86%D9%87%29 "آسیب پذیری چیست؟")های مبتنی بر وب:**  بعد از گذروندن مراحل بالا, حالا وقتش رسیده که برید سر قسمت پرهیجان و اصلی ماجرا, یعنی حملات و آسیب پذیری‌های رایج اپلیکیشن‌های وب! شما برای اینکه بتونید یک آسیب پذیری‌ رو پیدا و سپس [اکسپلویت](https://fa.wikipedia.org/wiki/%D8%A7%DA%A9%D8%B3%D9%BE%D9%84%D9%88%DB%8C%D8%AA "اکسپلویت چیست؟") کنید, باید بدونید اون آسیب پذیری چیه, چطوری بوجود میاد, و چطوری می‌شه اکسپلویتش کرد. برای آشنایی با این بخش می‌تونید از [OWASP TOP10](https://owasp.org/www-project-top-ten/ "OWASP TOP10") شروع کنید. این پروژه رایج‌ترین ریسک‌ها رو در دنیای امنیت وب به ده بخش تقسیم کرده که می‌تونید هر بخش رو جدا جدا سرچ کنید و یاد بگیرید.  
پیشنهاد می‌کنم کتاب [Web Application Security](https://www.oreilly.com/library/view/web-application-security/9781492053101/ "Web Application Security - Andrew Hoffman"), نوشته Andrew Hoffman رو هم از دست ندید. این کتاب آسیب پذیری‌های وب رو هم از دید تهاجمی, و هم از دید تدافعی مورد بررسی قرار داده و مطالعه اون می‌تونه دیدتون رو خیلی باز‌تر بکنه.

&nbsp;

## حل چلنج‌های CTF در حوزه وب, چه فایده‌ای داره وقتی می‌تونم هانت کنم و پول در بیارم؟

بیاید این مسئله رو باز‌تر کنیم...  
وقتی شما دانش وب هکینگ دارید, می‌تونید کار‌های مختلفی بکنید, از جمله تست نفوذ, هانت, رد تیم و... که همشون در دنیای واقعی انجام می‌شن. حالا بیاید به CTF در قالب یک تمرین, دستگرمی و بازی نگاه کنیم. چلنج‌های وب یک محیط شبیه سازی شده از سناریو‌های مختلف از خیلی آسون, تا خیلی سخت در اختیار شما قرار می‌دند. این سناریو‌ها بعضا در دنیای واقعی پیش میان, و بعضا فقط محدود به دنیای CTF هستند. تمرین و تکرار چلنج‌ها و سوالات مختلف می‌تونه به حضور ذهن شما کمک فراوانی بکنه و منجر بشه وقتی در اپلیکیشن‌های وب واقعی با یک مکانیزم روبرو شدید, سناریو‌های مختلفی براش داشته باشید و دست پر به جنگش برید.  
مورد بعدی که می‌تونم بهش اشاره کنم, افزایش مهارت و عمیق‌تر شدن دانش شما در وب هکینگ هست. همونطور که در توضیحات اول صفحه گفتم, این دسته از سوالات می‌تونن مهارت‌های مختلفی رو در شما پرورش بدند. شما کجا میخواید این همه سورس کد راحت و پیچیده ببینید و بشینید تحلیل‌شون کنید؟! D:   
<br/><br/>

## از کجا شروع کنم؟

اگر شما هم علاقمند هستید که دستی به حوزه وب ببرید, پیشنهادم به شما [picoCTF](https://picoctf.org/ "picoCTF") هست.picoCTF مسابقه‌ای هست که سالانه برگزار می‌شه و سوالاتش هم کاملا مناسب برای افراد مبتدی و تازه کار هستند, و نکته جالش هم این هست که بعد از اتمام زمان مسابقه, چلنج‌ها قابل دسترسی هستند و می‌تونید شروع به حل کردن بکنید.  
سعی کنید زمان بذارید و نا امید نشید, اگر صدتون رو گذاشتید و نتونستید چلنجی رو حل کنید, سرچ کنید و رایتاپش رو بخونید.