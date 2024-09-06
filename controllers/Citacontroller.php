<?php

namespace Controllers;

use MVC\Router;

Class CitaController{
    public static function index(Router $router){
       isAuth();
       $router->render('cita/index', [
           
           'nombre'=>$_SESSION['nombre'],
           'id'=>$_SESSION['id']
       ]);
       
    }
}