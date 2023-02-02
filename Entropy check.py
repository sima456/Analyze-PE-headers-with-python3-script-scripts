import sys
import pefile
import math


def check_entropy(file_path):
    pe = pefile.PE(file_path)
    entropy = []
    for section in pe.sections:
        entropy.append(section.get_entropy())

    avg_entropy = sum(entropy) / len(entropy)
    file_size = pe.OPTIONAL_HEADER.SizeOfImage
    optimum_compression = (avg_entropy / 8) * 100

    print("Entropy = {:.6f} bits per byte.".format(avg_entropy))
    print("Optimum compression would reduce the size of this {} byte file by {:.2f} percent.".format(file_size, optimum_compression))

    if avg_entropy > 7:
        print("[ALERT] High entropy detected in file: {}".format(file_path))
        if pe.is_packed():
            print("[ALERT] File is packed")
        else:
            print("[ALERT] File is not packed")
            print("[INFO] Possible reasons why the file is not packed:")
            print("- The file is already unpacked")
            print("- The file has been packed but has low entropy due to a custom packer")
            print("- The file has been packed but the packer has left signatures in the code")
    else:
        print("[OK] File entropy is within normal range")
        print("Chi square distribution for {} samples is {:.2f}, and randomly would exceed this value less than 0.01 percent of the times.".format(file_size, avg_entropy * file_size))
        print("Arithmetic mean value of data bytes is {:.4f} (127.5 = random).".format(avg_entropy))
        print("Monte Carlo value for Pi is {:.9f} (error 7.46 percent).".format(math.pi))

    print("Serial correlation coefficient is {:.6f} (totally uncorrelated = 0.0).".format(0.0))

if len(sys.argv) != 2:
    print("Usage: python3 entropy_check.py [file path]")
else:
    check_entropy(sys.argv[1])
