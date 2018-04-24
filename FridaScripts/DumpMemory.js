
Process.enumerateRanges("r--", {
        "onMatch": function (instance) {
                console.log("[*] " + instance.base + " : " + instance.size + " : " + instance.protection);
                var bytesRead = Memory.readByteArray(instance.base, instance.size)
                var fileName = "/sdcard/" + instance.base + "_dump.txt"
                var f = new File(fileName, "wb")
                f.write(bytesRead)
                f.close()
        },
        "onComplete": function () {
        }
});
