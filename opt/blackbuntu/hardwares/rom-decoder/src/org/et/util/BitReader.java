package org.et.util;

public class BitReader
{
    private char abBuff[];
    private int iNdx;

    public BitReader(char b[])
    {
        abBuff = b;
        iNdx = 0;
    }

    public short readBit()
    {
        return readBitNdx(iNdx++);
    }
    // Max return size 64 bit;
    public long readBit(int iCount)
    {
        long lRes = 0;
        for(int iNdx=0;iNdx<iCount;iNdx++)
        {
            lRes <<= 1;
            lRes |= (readBit() & 0x1);
        }
        return lRes;
    }

    public short readByte()
    {
        return (short)readBit(8);
    }

    public short readBitNdx(int iNdx)
    {
        int iByte = iNdx/8;
        int iBit = iNdx%8;

        if(iByte>=abBuff.length)
            throw new ArrayIndexOutOfBoundsException();
        return (short)(((abBuff[iByte] & (1<<(7-iBit))) == 0) ? 0 : 1);
    }
}

