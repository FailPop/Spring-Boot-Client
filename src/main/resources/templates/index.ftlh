<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Input Page</title>
</head>
<body>
<h1>Введите сообщение</h1>
<form action="/sendMessage" method="post">
    <input type="text" name="message" placeholder="Ваше сообщение" required>
    <button type="submit">Отправить</button>
</form>
</body>
</html>
