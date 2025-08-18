<?php
$application->connectDb();
$application->initSession();
$application->initPlugins();

ob_start();

try {
    
    $source = file_get_contents('php://input');	
    $requestBody = json_decode($source, true);

    $headers = getallheaders();
    
    print_r($requestBody);
    print_r($headers);

	$order = \Sale\Order::getById( $requestBody['transaction']['orderId'] );
	$gateway = $order->getPaymentGateway();
    

    if($requestBody['event'] == 'payment'){

        $hash = hash_hmac ( "sha256" , implode('|',[
            $requestBody['transaction']['amount'],
            $gateway->params['MerchantId'],
            $requestBody['transaction']['orderId'],
            $requestBody['transaction']['status']['value'],
            $requestBody['transaction']['status']['date'],
        ]), $gateway->params['secretKey']);
        if ($hash != $headers['X-Api-Signature-Sha256']) {
            throw new \Exception('X-Api-Signature check failed');
        }
        $gateway->saveTransaction($requestBody['transaction']['id'], $requestBody);
        if  ($requestBody['transaction']['status']['value'] == 'SUCCESS') {
            $order->paymentSuccess();
            $gateway->sendReceiptSell();
        }
        file_put_contents($_SERVER['DOCUMENT_ROOT'] . '/uploads/logs/raiff.log', date('Y.m.d H:i:s')." ".$_SERVER['QUERY_STRING']." ".$_SERVER['REMOTE_ADDR']." "var_dump($requestBody)."\n", FILE_APPEND);
        header("HTTP/1.1 200 OK");
        print 'OK';		
    }
    if(isset($requestBody['refund']) && !empty($requestBody['refund'])){

        $hash = hash_hmac ( "sha256" , implode('|',[
            $requestBody['refund']['amount'],
            $gateway->params['MerchantId'],
            'refund'.$requestBody['refund']['id'],
            $requestBody['refund']['status']['value'],
            $requestBody['refund']['status']['date'],
        ]), $gateway->params['secretKey']);
        
        if ($hash != $headers['X-Api-Signature-Sha256']) {
            throw new \Exception('X-Api-Signature check failed');
        }
        
        header("HTTP/1.1 200 OK");
        print 'OK';		
    }
			
	
}
catch (\Exception $e) {
	
	header( "HTTP/1.1 500 ".trim(preg_replace('/\s+/', ' ', $e->getMessage())) );
	print $e->getMessage();
	 
}

/*$data = ob_get_contents();
ob_end_flush();
file_put_contents(__DIR__.'/log'.time().'.txt', $data);*/
