import pefile
import sys
import os

#RUN pip3 install pefile before compilation
# Loading an executable
filepath = sys.argv[1]
targetVirtualAddressParam = sys.argv[2]


def CheckForValidFilePath(filepath):
    a = os.path.exists(filepath)
    if a == False:
        print("This value is not a valid file path, terminating program!")
        exit(1)
    return


def CheckForValidInput(targetVirtualAddressParam):
    try:
        int(targetVirtualAddressParam, 16)
        return
    except ValueError:
        print("This value is not a valid hexadecimal number, terminating program!")
        exit(1)


def ConvertTargetVirtualAddressToTargetPointer(filename, targetVirtualAddressParam):
    for section in pe.sections:
        #values in next line are being treated as a string fix this
        if hex(section.VirtualAddress) + hex(section.Misc_VirtualSize) < targetVirtualAddress:
            resultSection = section
            break
    offset = int(targetVirtualAddress,16) - resultSection.VirtualAddress
    print(type(offset))
    targetFilePointer = resultSection.PointerToRawData + offset
    print(str(targetVirtualAddress) + "  -> " + str(hex(targetFilePointer)))


if __name__ == '__main__':
    filepath = sys.argv[1]
    targetVirtualAddressParam = sys.argv[2]
    CheckForValidFilePath(filepath)
    CheckForValidInput(targetVirtualAddressParam)
    targetVirtualAddress = hex(int(targetVirtualAddressParam, 16))
    pe = pefile.PE(str(filepath))
    ConvertTargetVirtualAddressToTargetPointer(filepath, targetVirtualAddressParam)
