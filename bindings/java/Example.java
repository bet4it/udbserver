import unicorn.Unicorn;
import udbserver.Udbserver;

public class Example {

   public static final int ADDRESS = 0x1000;
   public static final byte[] ARM_CODE = {(byte)0x0f, (byte)0x00, (byte)0xa0, (byte)0xe1, (byte)0x14, (byte)0x00, (byte)0x80, (byte)0xe2, (byte)0x00, (byte)0x10, (byte)0x90, (byte)0xe5, (byte)0x14, (byte)0x10, (byte)0x81, (byte)0xe2, (byte)0x00, (byte)0x10, (byte)0x80, (byte)0xe5, (byte)0xfb, (byte)0xff, (byte)0xff, (byte)0xea};

   public static void main(String args[])
   {
       Unicorn u = new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_ARM);
       u.mem_map(ADDRESS, 0x400, Unicorn.UC_PROT_ALL);
       u.mem_write(ADDRESS, ARM_CODE);
       Udbserver.Udbserver(u, (short)1234, 0x1000);
       u.emu_start(0x1000, 0x2000, 0, 0x1000);
       u.close();
   }

}
