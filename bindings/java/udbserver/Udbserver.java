package udbserver;
import unicorn.Unicorn;

public class Udbserver {

    static {
        System.loadLibrary("udbserver_java");
    }

    public static void Udbserver(Unicorn unicorn, short port, long start_addr) {
       udbserver(unicorn.eng, port, start_addr);
    }

    private static native void udbserver(long addr, short port, long start_addr);
}
