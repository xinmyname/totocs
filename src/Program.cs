using System;

namespace totocs {

    class Program {
        
        static void Main(string[] args) {
            var otp = new OneTimePassword("please send your answer to big pig care of the funny farm");
            Console.WriteLine(otp.Generate());
        }
    }
}
