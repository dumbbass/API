<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Template</title>
    <style>
        /* General styles */
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            margin: 0;
            padding: 0;
        }

        .container {
            max-width: 600px;
            margin: 50px auto;
            background-color: #fff;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .banner {
            background-image: url('https://drive.google.com/uc?id=1xcvRaQ2KQj5062V9SXsRKkrv3rAR6VFU');
            background-size: 40% auto;
            background-position: center;
            background-repeat: no-repeat;
            height: 125px;
        }

        .header {
            border-top-right-radius: 10px;
            border-top-left-radius: 10px;
            background-color: #0073e6;
            color: #fff;
            padding: 20px;
            text-align: center;
        }

        .header h1 {
            margin: 0;
            font-size: 24px;
        }

        .content {
            padding: 20px;
            text-align: center;
        }

        .content p {
            color: #333;
            line-height: 1.6;
        }

        .qr-code-container {
            margin: 20px auto;
            width: 120px;
        }

        .qr-code-container img {
            width: 100%;
            border: 2px solid #0073e6;
            border-radius: 10px;
        }

        .footer {
            background-color: #0073e6;
            color: #fff;
            padding: 10px;
            text-align: center;
            font-size: 12px;
        }

        .link {
            color: #0073e6;
            text-decoration: none;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="banner"></div>
        <div class="header">
            <h1>Greetings!</h1>
        </div>
        <div class="content">
            <p>You have been invited to attend!</p>
            <p>Please scan the QR code below to go to the form:</p>
            <div class="qr-code-container">
                <img src="cid:qr_code_image" alt="QR Code">
            </div>
            <p>or click this link: <a href="<?php echo $qrCodeData; ?>" class="link"><?php echo $qrCodeData; ?></a></p>
            <p><?php echo $message; ?></p>
        </div>
        <div class="footer">
            <p>&copy; 2024 CEPA. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
