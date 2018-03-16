using System;

namespace totocs {

    class Program {
        
        static void Main(string[] args) {
            var factory = new OneTimePasswordFactory("please send your answer to big pig care of the funny farm");
            Console.WriteLine(factory.Generate());
        }
    }
}
