<?php

namespace Controllers;

use Classes\Email;
use Model\Usuario;
use MVC\Router;

class LoginController {
    public static function login(Router $router) {
        $alertas = [];
        $auth = new Usuario();
        
        if( $_SERVER['REQUEST_METHOD'] === 'POST') {
            $auth = new Usuario($_POST);
            $alertas = $auth->validarLogin();

            if(empty($alertas)) {
                $usuario = Usuario::where('email', $auth->email);
                
                if($usuario) {
                    //Verificar el password
                    if($usuario->comprobarPasswordAndVerificado($auth->password)){
                        //Autenticar el usuario
                        session_start();

                        $_SESSION['id'] = $usuario->id;
                        $_SESSION['nombre'] = $usuario->nombre . " ". $usuario->apellido;
                        $_SESSION['email'] = $usuario->email;
                        $_SESSION['login'] = true;

                        //Redireccionamiento
                        if($usuario->admin=== '1') {
                            $_SESSION['admin'] = $usuario->admin ?? null;
                            header('Location: /admin');

                        } else {
                            header('Location: /cita');                            
                        }

                        debuguear($_SESSION);
                    }                    

                } else {
                    Usuario::setAlerta('error', 'Password incorrecto o usuario no encontrado');
                }
            }
        }

        $alertas = Usuario::getAlertas();      
        $router->render ('auth/login', [
            
            'alertas'=>$alertas
        ]);
    }
    
    public static function logout() {
       $_SESSION = [];
    //    debuguear($_SESSION);
        header('Location: /');
    }

    public static function olvide(Router $router) {
        $alertas = [];

        if($_SERVER ['REQUEST_METHOD'] === 'POST'){
            $auth = new Usuario($_POST);
            $alertas = $auth->validarEmail();
            
            if(empty($alertas)){
                $usuario = Usuario::where('email', $auth->email);
                
                if($usuario && $usuario->confirmado){
                    //Crear token
                    $usuario->crearToken();
                    $usuario->guardar();
                    //Enviar mail
                    $email = new Email($usuario->nombre, $usuario->email, $usuario->token);
                    $email->enviarInstrucciones();
                    //alertas
                    $alertas = Usuario::setAlerta('exito', 'Revisa tu email');                    
                    
                } else {
                    $alertas = Usuario::setAlerta('error', 'El usuario no existe o no está confirmado');                    
                }
                
                $alertas = Usuario::getAlertas();
            }
            
        }

        $router->render('auth/olvide-password', [
            'alertas'=> $alertas
        ]);
    
        
    }

    public static function recuperar(Router $router) {
        $alertas = [];
        $token = $_GET[s('token')];
        $error = false;

        //Buscar usuario por su token
        $usuario = Usuario::where('token', $token);
        

        //Crear alerta
        if(empty($usuario)) {
            Usuario::setAlerta('error', 'Token no válido');
            $error = true;
        }

        if($_SERVER['REQUEST_METHOD'] === 'POST'){
           //Leer nuevo password y guardarlo
           $password = new Usuario($_POST);
           $alertas = $password->validarPassword();
           if(empty($alertas)){
                $usuario->password = null;
                $usuario->password = $password->password;
                $usuario->hashPassword();
                $usuario->token = null;

                $resultado=$usuario->guardar();
                if($resultado){
                    header('Location: /cita');
                }
               
            }
        }

        $alertas = Usuario::getAlertas();
        $router->render('auth/recuperar-password', [
            'alertas'=>$alertas,
            'error'=>$error
            
        ]);
      
    }

    public static function crear(Router $router) {

        $usuario = new Usuario;

        //Alertas vacías
        $alertas = [];

        if( $_SERVER['REQUEST_METHOD'] === 'POST') {
            $usuario->sincronizar($_POST);
            $alertas = $usuario->validarNuevacuenta();

            //Revisar que alertas esté vacío
            if(empty($alertas)){
                //Verificar que el usuario no este registrado
                $resultado = $usuario->existeUsuario();

                if($resultado->num_rows) {
                    $alertas = Usuario::getAlertas();
                } else {
                    //Hashear password
                    $usuario->hashPassword(); 
                    
                    //Crear token
                    $usuario->crearToken();
                    
                    //Enviar email
                    $email = new Email($usuario->nombre, $usuario->email, $usuario->token);
                    $email->enviarConfirmacion();
                    
                    //Guardar usuario
                    $resultado = $usuario->guardar();

                    //Redireccionar usuario para msj
                    if ($resultado){
                        (header('Location: /mensaje'));
                      
                    }

                    // debuguear($usuario);
                }
        
            }

        }

        $router->render('auth/crear-cuenta', [
            'usuario'=>$usuario,
            'alertas'=>$alertas

        ]);

    }

    public static function mensaje(Router $router) {
        $router->render('auth/mensaje');
        
    }
    
    public static function confirmar(Router $router) {

        $alertas = [];
        $token = s($_GET['token']);

        $usuario = Usuario::where('token', $token);

        if(empty($usuario)) {
            Usuario::setAlerta('error', 'Token no válido');
        } else {
            $usuario->confirmado = "1";
            $usuario->token = "null";
            $usuario->guardar();
            Usuario::setAlerta('exito', 'Token válido');
        }
        
        $alertas = Usuario::getAlertas();
        $router->render('auth/confirmar-cuenta', [
            'alertas'=>$alertas
        ]);
        
    }

    public static function cita(Router $router) {
        $router->render('auth/cita');
        
    }

    public static function admin(Router $router) {
        $router->render('auth/admin');
        
    }
}