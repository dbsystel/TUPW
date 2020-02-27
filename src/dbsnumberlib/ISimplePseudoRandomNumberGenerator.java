package dbsnumberlib;

public interface ISimplePseudoRandomNumberGenerator {
      public long nextLong();
      public int nextInt();
      public short nextShort();
      public byte nextByte();

      public long nextLong(long fromInclusive, long toInclusive);
      public int nextInt(int fromInclusive, int toInclusive);
      public short nextShort(short fromInclusive, short toInclusive);
      public byte nextByte(byte fromInclusive, byte toInclusive);
}
