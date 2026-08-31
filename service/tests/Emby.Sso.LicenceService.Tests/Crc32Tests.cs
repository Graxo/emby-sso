using System.Text;
using Xunit;

namespace Emby.Sso.LicenceService.Tests
{
    /// <summary>
    /// The CRC that goes inside PayPal's signed message. If this is wrong,
    /// nothing PayPal sends will ever verify - so it is checked against the
    /// published vectors for CRC-32/ISO-HDLC rather than against itself.
    /// </summary>
    public class Crc32Tests
    {
        [Theory]
        [InlineData("123456789", 0xCBF43926u)]
        [InlineData("", 0x00000000u)]
        [InlineData("a", 0xE8B7BE43u)]
        [InlineData("The quick brown fox jumps over the lazy dog", 0x414FA339u)]
        public void Matches_the_published_vectors(string input, uint expected)
        {
            Assert.Equal(expected, PayPal.Crc32.Compute(Encoding.ASCII.GetBytes(input)));
        }

        [Fact]
        public void One_changed_byte_changes_the_crc()
        {
            var body = Encoding.UTF8.GetBytes("{\"event_type\":\"PAYMENT.CAPTURE.COMPLETED\"}");
            var tampered = (byte[])body.Clone();

            tampered[10] ^= 0x01;

            Assert.NotEqual(PayPal.Crc32.Compute(body), PayPal.Crc32.Compute(tampered));
        }
    }
}
