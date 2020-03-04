package dbsnumberlib;

public interface ISimplePseudoRandomNumberGenerator {
      long nextLong();
      int nextInt();
      short nextShort();
      byte nextByte();

      long nextLong(long fromInclusive, long toInclusive);
      int nextInt(int fromInclusive, int toInclusive);
      short nextShort(short fromInclusive, short toInclusive);
      byte nextByte(byte fromInclusive, byte toInclusive);
}
