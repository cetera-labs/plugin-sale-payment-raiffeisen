<?php
$application->connectDb();
$application->initSession();
$application->initPlugins();

ob_start();

try {
    $source = file_get_contents('php://input');	
    $requestBody = json_decode($source, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new \Exception('Invalid JSON: ' . json_last_error_msg());
    }

    $headers = function_exists('getallheaders') ? getallheaders() : [];
    $signature = null;
    foreach ($headers as $key => $value) {
        if (strtolower($key) === 'x-api-signature-sha256') {
            $signature = $value;
            break;
        }
    }
    if (!$signature && isset($_SERVER['HTTP_X_API_SIGNATURE_SHA256'])) {
        $signature = $_SERVER['HTTP_X_API_SIGNATURE_SHA256'];
    }

    $event = strtolower($requestBody['event'] ?? '');

    if ($event === 'payment') {
        $order = \Sale\Order::getById($requestBody['transaction']['orderId']);
        if (!$order) {
            throw new \Exception('Order not found');
        }
        
        $gateway = $order->getPaymentGateway();

        $hash = hash_hmac("sha256", implode('|', [
            $requestBody['transaction']['amount'],
            $gateway->params['MerchantId'],
            $requestBody['transaction']['orderId'],
            $requestBody['transaction']['status']['value'],
            $requestBody['transaction']['status']['date'],
        ]), $gateway->params['secretKey']);

        if ($hash !== $signature) {
            throw new \Exception('X-Api-Signature check failed');
        }

        $gateway->saveTransaction($requestBody['transaction']['id'], $requestBody);
        
        if (strtoupper($requestBody['transaction']['status']['value']) === 'SUCCESS') {
            $order->paymentSuccess();
            $gateway->sendReceiptSell();
        }

        header("HTTP/1.1 200 OK");
        print 'OK';		
    }
    elseif ($event === 'refund') {
        $tx = $requestBody['transaction'] ?? [];
        
        
        $hash = hash_hmac("sha256", implode('|', [
            $tx['amount'] ?? 0,
            $gateway->params['MerchantId'],
            'refund' . ($tx['id'] ?? ''),
            $tx['status']['value'] ?? '',
            $tx['status']['date'] ?? '',
        ]), $gateway->params['secretKey']);
        
        if ($hash !== $signature) {
            throw new \Exception('X-Api-Signature check failed for refund');
        }
        
        header("HTTP/1.1 200 OK");
        print 'OK';		
    }
    else {
        header("HTTP/1.1 200 OK");
        print 'Unknown event';
    }
	
} catch (\Exception $e) {
    header("HTTP/1.1 500 " . trim(preg_replace('/\s+/', ' ', $e->getMessage())));
    print $e->getMessage();
}

$logData = ob_get_contents();
ob_end_clean();
