#!msh 

$port= new-Object System.IO.Ports.SerialPort COM4,115200,None,8,one
$port.Open()
While (1) {
    $port.ReadLine()
}