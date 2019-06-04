using EncryptionAlgorithm.UtilityTools;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithm
{
    class Program
    {
        static void Main(string[] args)
        {
            
            String strOracleE = CryptographyUtilt.EncryptDES("Oracle");
            String strOracleD = CryptographyUtilt.DecryptDES("Oracle");

            Debug.WriteLine("DES Encrypt >>>>>>>>>>>> " + strOracleE);
            Debug.WriteLine("DES Encrypt >>>>>>>>>>>> " + strOracleD);
        }
    }
}
