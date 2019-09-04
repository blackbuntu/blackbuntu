package org.et;

import java.util.ArrayList;
import java.util.List;

import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;

import org.et.util.BitReader;
import org.apache.commons.collections4.queue.CircularFifoQueue;

public class rom0
{
    public static void main(String asArg[])
    {
        if(asArg.length==0)
        {
            System.out.println("java org.et.rom0 <file input>");
            return;
        }
        File objInput = new File(asArg[0]);
        byte abBuff[] = null;
        try {
            FileInputStream reader = new FileInputStream(objInput);
            abBuff = new byte[(int) objInput.length()];
            reader.read(abBuff);
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        char abDecomp[] = null;
        for(int iNdx=3;iNdx<abBuff.length; iNdx++)
        {
            if (abBuff[iNdx-3] == (byte)0xCE && abBuff[iNdx-2] == (byte)0xED &&
                abBuff[iNdx-1] == (byte)0xDB && abBuff[iNdx] == (byte)0xDB)
            {
                char abBuff2[] = new char[abBuff.length-iNdx];
                for(int iNdx2=iNdx-3,iNdx3=0;iNdx3<abBuff.length-iNdx;iNdx2++,iNdx3++)
                    abBuff2[iNdx3] = (char)(abBuff[iNdx2] & 0xFF);
                abDecomp = decompress(abBuff2);
                break;
            }
        }
        for(int iNdx=0;iNdx<abDecomp.length;iNdx++)
        {
            if(abDecomp[iNdx]<32 || abDecomp[iNdx]>0x7E)
                System.out.print('.');
            else
                System.out.print(abDecomp[iNdx]);
        }
    }

    private static char[] decompress(char abBuff[])
    {
        List<Character> mylist = new ArrayList<Character>();
        int iNdx = 0;
        int unknown = abBuff[iNdx++] << 24 | abBuff[iNdx++] << 16 | abBuff[iNdx++] << 8 | abBuff[iNdx++];
        int majorVersion = abBuff[iNdx++] << 8 | abBuff[iNdx++];
        int minorVersion = abBuff[iNdx++] << 8 | abBuff[iNdx++];
        int blockSize = abBuff[iNdx++] << 24 | abBuff[iNdx++] << 16 | abBuff[iNdx++] << 8 | abBuff[iNdx++];
        while(iNdx < abBuff.length)
        {
            int orgSize = abBuff[iNdx++] << 8 | abBuff[iNdx++];
            int rawSize = abBuff[iNdx++] << 8 | abBuff[iNdx++];
            char abCompress[] = new char[rawSize];
            for(int iNdx2=iNdx, iNdx3 = 0;iNdx3<abCompress.length;iNdx2++,iNdx3++)
                try {
                    abCompress[iNdx3] = (char)(abBuff[iNdx2] & 0xFF);
                }catch(ArrayIndexOutOfBoundsException a) {
                    break;
                }
            List<Character> l = null;
            try {
                l = decomp(abCompress);
            }catch(ArrayIndexOutOfBoundsException a) {
                break;
            }
            mylist.addAll(l);
            iNdx += rawSize;
        }
        char abRet[] = new char[mylist.size()];
        iNdx = 0;
        for(char b : mylist)
            abRet[iNdx++] = b;
        return abRet;
    }
    private static List<Character> decomp(char[] abBuff)
    {
        List<Character> objRet = new ArrayList<Character>();
        CircularFifoQueue<Character> window = new CircularFifoQueue<Character>(2048);
        BitReader objBitRead = new BitReader(abBuff);
        for(int iNdx=0;iNdx<2048;iNdx++)
            window.add('\0');
        while (true)
        {
            int bit = objBitRead.readBit();
            if (bit==0)
            {
                int character = objBitRead.readByte();
                objRet.add((char)character);
                window.add((char)character);
            }
            else
            {
                int offset;
                bit = objBitRead.readBit();
                if (bit==1)
                {
                    offset = (int)objBitRead.readBit(7);
                    if (offset == 0)
                    {
                        //end of file
                        break;
                    }
                }
                else
                {
                    offset = (int)objBitRead.readBit(11);
                }
                int len;
                int lenField = (int)objBitRead.readBit(2);
                if (lenField < 3)
                {
                    len = lenField + 2;
                }
                else
                {
                    lenField <<= 2;
                    lenField += (int)objBitRead.readBit(2);
                    if (lenField < 15)
                    {
                        len = (lenField & 0x0f) + 5;
                    }
                    else
                    {
                        int lenCounter = 0;
                        lenField = (int)objBitRead.readBit(4);
                        while (lenField == 15)
                        {
                            lenField = (int)objBitRead.readBit(4);
                            lenCounter++;
                        }
                        len = 15*lenCounter + 8 + lenField;
                    }
                }
                for (int i = 0; i < len; i++)
                {
                    char character = (char)window.get(offset);
                    objRet.add(character);
                    window.add(character);
                }
            }
        }
        return objRet;
    }
}
