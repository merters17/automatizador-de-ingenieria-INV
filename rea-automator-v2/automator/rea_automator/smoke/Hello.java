package rea.smoke;

/**
 * Clase mínima para la prueba de humo de JADX (rea_automator.jadx_tool.check_jadx).
 *
 * Se compiló con:  javac --release 8 -g:none -d <dir> Hello.java
 * y el resultado (rea/smoke/Hello.class) se guardó como Hello.class en esta carpeta.
 * JADX debe reconstruir una clase `Hello` con el literal "hola-jadx-smoke:" y la
 * llamada add(2, 3). Los nombres de los parámetros se pierden a propósito (-g:none),
 * así que la prueba no depende de ellos.
 */
public class Hello {
    public static int add(int a, int b) {
        return a + b;
    }

    public static String greet(String name) {
        return "hola-jadx-smoke:" + name + ":" + add(2, 3);
    }
}
