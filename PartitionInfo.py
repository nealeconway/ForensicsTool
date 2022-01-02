# Data Forensic Tool
# Program to display partition details
# Author: Radhakrishna Prabhu, Neale Conway, Aanuoluwa Babasanmi
import struct
import sys
try:
    file = open(sys.argv[1], "rb")          # Open the image file provided as input from the commandline in binary format
    file.seek(0x1Be)                        # To Access the partition table details from the MBR which is after 446 bytes
except:
    print("Incorrect file entry, please check!!"), sys.exit()

#Creating variables
sectorStart = []                        # List which stores the start sector address of the partition
partitionType = []                      # List which stores the type of partition
partitionSize = []                      # List which stores the size of each partition
ntfs_part_start_addr = []               # List which stores NTFS partition starting sector address
sector_size = 512                       # Sector size is set as 512 bytes
dir_entry_size = 32                     # Directory entry size set as 32 bytes
offset = 16                             # Offset of 16 bytes
partition_info = file.read(64)          # Reading 64 bytes of MBR which contains the partition table entry information
partition_table_entry = {               # Dictionary used for mapping only the required fields for this program from the partition table entry
    "parttype":0x04,                    # Partition type
    "sectorstart":0x08,                 # Starting LBA address
    "partsize":0x0C                     # Size of partition in sectors
}
partition_type = {                      # Dictionary of partition type codes
        0:"Unknown/Empty",
        1:"12-bit FAT",
        4:"16-bit FAT",
        5:"Extended MS-DOS Partition",
        6:"FAT-16",
        7:"NTFS",
        11:"FAT-32(CHS)",
        12:"FAT-32(LBA)",
        14:"FAT-16(LBA)"
        }

# Function description: Function to discover and print details of different partitions of the disk image file.
# Parameter: None
# Return: Variable flag to indicate if NTFS Partition exists.
def display_partition_information():
    j=0                             # Used to track the NTFS partition number
    valid_partition_count=0         # Used to track all the valid partition in the sample disk provided
    ntfs_partition_number=[]        # List which stores the partition number for type NTFS
    ntfs_exist=False                # Flag used to indicate if NTFS partition type exist or not
    for i in range(4):       # Maximum number of standard partitions in MBR is 4.
        # Extracting type of partition and adding it to the list
        partitionType.append(partition_info[partition_table_entry["parttype"] + (i * offset)])
        # Checking if partition is valid or not
        if (partitionType[i] != 0):
            valid_partition_count = valid_partition_count + 1
        # Extracting 4 bytes to find starting sector address of each partition and adding it to the list
        # Using struct unpack to convert the bytearray to string. "<" is to indicate data is in Little Endian format, "L" is used to indicate value of type unsigned long of size 4 bytes and [0] is to get the value from the tuple.
        sectorStart.append(struct.unpack("<L",bytearray(partition_info[(partition_table_entry["sectorstart"] + (i * offset)):(partition_table_entry["sectorstart"] + (i * offset) + 4)]))[0])
        # Extracting size of each partition and adding it to the list
        partitionSize.append(struct.unpack("<L", bytearray(partition_info[(partition_table_entry["partsize"] + (i * offset)):(partition_table_entry["partsize"] + (i * offset) + 4)]))[0])
    # Printing the captured partition details and using zip function to iterate across all 3 lists in pairs
    print("\n----------------------------")
    print("Partition information\n----------------------------")
    for part_type, sector_start, part_size in zip(partitionType, sectorStart, partitionSize):
        print("Partition %d\tType:%s  |  Start Sector:%d  |  Partition Size:%d  |" % (j, partition_type[part_type], sector_start, part_size))
        # Checking if partition type is NTFS and setting NTFS flat to true while tracking the partition number
        if(partition_type[part_type]=="NTFS"):
            ntfs_partition_number.append(j)
            if(ntfs_exist==False):
                ntfs_exist=True
        j = j + 1
    # Printing total number of valid partitions
    print("Total number of valid partitions are", valid_partition_count)
    # Adding starting sector of all NTFS partition type to the list
    for i in ntfs_partition_number:
        ntfs_part_start_addr.append(sectorStart[i])
    return ntfs_exist

# Function description: Function to display information of the first partition.
# Parameter: None
# Return: cluster#2 sector address and sector address of data area.
def display_first_partition_information():

    file.seek(sectorStart[0] * sector_size)                      # Seek to the starting sector of the first partition
    first_partition = file.read(64)                              # Reading the first 64 bytes of partition one which has the necessary information
    first_partition_sectors_per_cluster = first_partition[0xD]   # No. of sectors per cluster
    first_partition_no_of_FAT_copies = first_partition[0x10]     # Number of copies of FAT
    #Size of each FAT is of 2 bytes and hence need to extract the array, order in little endian and convert to type int.
    first_partition_sizeof_each_FAT = int.from_bytes(bytearray(first_partition[0x16:0x18]), byteorder='little')
    #Calculating the size of FAT area
    first_partition_sizeof_FAT_area = first_partition_sizeof_each_FAT * first_partition_no_of_FAT_copies
    #Maximum number of root directory is of 2 bytes size and hence need to extract the array, order in little endian and convert to type int.
    #This would be needed while calculating the size of root directory.
    first_partition_max_no_of_rootdirectory = int.from_bytes(bytearray(first_partition[0x11:0x13]), byteorder='little')
    #Calculating size of root directory
    first_partition_rootdirectory_size = (first_partition_max_no_of_rootdirectory * dir_entry_size) / sector_size
    #Size of reserved area is of 2 bytes and hence need to extract the array, order in little endian and convert to type int.
    #This would be needed while calculating the sector address of data area.
    first_partition_reserved_area = int.from_bytes(bytearray(first_partition[0xE:0x10]), byteorder='little')
    #Calculating sector address of start of the data area
    first_partition_DA = sectorStart[0] + first_partition_reserved_area + first_partition_sizeof_FAT_area
    #Calculating cluster#2 sector address
    cluster2_sector_address = first_partition_DA + first_partition_rootdirectory_size
    #Print values
    print("\n----------------------------")
    print("Details of first partition\n----------------------------")
    print("Number of sectors per cluster: %d \n"
          "Size of the FAT Area: %d sectors \n"
          "Size of the Root Directory: %d sectors \n"
          "Sector address of Cluster #2: %d" % (first_partition_sectors_per_cluster, first_partition_sizeof_FAT_area, first_partition_rootdirectory_size, cluster2_sector_address))
    return cluster2_sector_address,first_partition_DA            # Return these for calculating the information of the first deleted file in this partition.

# Function description: Function to display information of the first deleted file.
# Parameter: The sector address of cluster #2, the address of the first partitions data area.
# Return: None
def displayDeletedFileInformation(cluster2_sector_add, partition_one_da):

    root_dir = partition_one_da * sector_size
    # Loop starts at the address for the partitions data area. The loop interates 32 bytes at a time to find the first deleted file.
    for x in range(root_dir, int(cluster2_sector_add * sector_size), 32):
        file.seek(x)
        find_deleted_file = file.read(2)
        if(find_deleted_file[0]  == 229):
            file.seek(x)
            find_deleted_file = file.read(32)
            break
    # Handling the event that no deleted files are found in the disk.
    if (find_deleted_file[0] != 229):
        print("There is no deleted file information on this disks root directory")
        return
    # Converts the name of file to a string.
    string_file_name = ''.join(map(chr, find_deleted_file[0:11]))
    string_file_name = string_file_name[:-3] + '.' + string_file_name[-3:]
    string_file_name = string_file_name.replace(" ","")
    # The size of the deleted file is 4 bytes in size and is coverted to type int.
    size_of_deleted_file = int.from_bytes(bytearray(find_deleted_file[0x1C:0x1F]), byteorder='little')
    # The number of the first cluster is of size 2 bytes and is coverted to type int.
    first_cluster_number = int.from_bytes(bytearray(find_deleted_file[0x1A:0x1B]), byteorder='little')
    # Calculating the Cluster Sector address.
    CSA = int(cluster2_sector_add) + ((first_cluster_number - 2) * 8)
    # To find the contents of the deleted file.
    file.seek(CSA * sector_size)
    # Reads the first 16 characters of the contents of the deleted file.
    deleted_file_contents = bytearray(file.read(16))
    # Converts the contents of the deleted file into a string.
    string_file_contents = ''.join(map(chr, deleted_file_contents))

    # Print Values
    print("\n----------------------------")
    print("Details of first deleted file\n----------------------------")
    print("The name of the deleted file: %s\n"
    "The size of the deleted file: %d\n"
    "The number of the first cluster: %d\n"
    "Cluster sector address: %d\n"
    "First 16 characters of the deleted file: %s"% (
    string_file_name, size_of_deleted_file, first_cluster_number,
    CSA, string_file_contents))


def display_ntfs_information():
    start_of_MFT = []                                   # List which stores the start sector address of the $MFT record
    attributes_type={                                   # Dictionary that stores attributes types
        0:"Non-resident",
        16:"$STANDARD_INFORMATION",                  
        32:"$ATTRIBUTE_LIST",
        48:"$FILE_NAME",
        64:"$VOLUME VERSION",
        64:"$OBJECT_ID",
        80:"$SECURITY_DESCRIPTOR",
        96:"VOLUME_NAME",
        122:"VOLUME_INFORMATION",
        128:"DATA",
        144:"$INDEX_ROOT",
        160:"INDEX_ALLOCATION",
        176:"BITMAP",
        192:"REPARSE_POINT",
        256:"$LOGGED_UTILITY STREAM"
    }
    if (ntfs_exist==True):
        file.seek(ntfs_part_start_addr[0] * sector_size)    # seek starting address of the ntfs partition
        ntfs_partition=file.read(64)                        # read first 64 bits which has all the neccessary information
        #ntfs bytes per sector is a word hence the need to order in big endian and convert to int
        ntfs_bytes_per_sector= int.from_bytes(bytearray(ntfs_partition[0x0B:0x0D]), byteorder='big')
        ntfs_sectors_per_cluster= ntfs_partition[0x0D] #sector per cluster of ntfs partition
        #ntfs bytes per sector is longlong hence the need to order in little endian and convert to int
        ntfs_logical_cluster_MFT= int.from_bytes(bytearray(ntfs_partition[0x30:0x38]), byteorder='little')
        #ntfs sector address= ntfs sectors per cluster * logical cluster of $MFT
        ntfs_sector_address=ntfs_sectors_per_cluster*ntfs_logical_cluster_MFT
        #starting address of the $MFT = ntfs sector address + starting address of the ntfs partition
        start_of_MFT.append(ntfs_sector_address+ntfs_part_start_addr[0])
        #print values   
        print("\n-------------------------------")
        print("Details of NTFS partition\n-----------------")
        print("Bytes per Sector: %d \n"
             "Sector per Cluter: %d \n"
             "Sector Address of the $MFT Record: %d" % (ntfs_bytes_per_sector, ntfs_sectors_per_cluster, ntfs_sector_address))
        
        file.seek(start_of_MFT[0] * sector_size)            # seek starting address of the $MFT Record
        mft_attributes=file.read(256)                       # read first 256 bits which has all the neccessary information
        mft_first_attribute_type=mft_attributes[0x38]       # first attribute type
        # first attribute length is four bytes hence the need to order in big endian and convert to int
        first_attribute_length= int.from_bytes(bytearray(mft_attributes[0x39:0x3D]), byteorder='big')
        #print values
        print("\n-------------------------------")
        print("Details of First $MFT Attributes\n-----------------------------------")
        print("Type:%s\n"
              "Length: %d" % (attributes_type[mft_first_attribute_type], first_attribute_length))
        mft_second_attribute_type = mft_attributes[0x98]    # second attribute type
        # second attribute length is four bytes hence the need to order in big endian and convert to int
        second_attribute_length= int.from_bytes(bytearray(mft_attributes[0x99:0x9D]), byteorder='big')
        #print values
        print("\n-------------------------------")
        print("Details of Second $MFT Attributes\n---------------------------------")
        print("Type:%s\n"
              "Length: %d" % (attributes_type[mft_second_attribute_type], second_attribute_length))


#Function calls
ntfs_exist=display_partition_information()
cluster2_sector_add,partition_one_da=display_first_partition_information()
displayDeletedFileInformation(cluster2_sector_add, partition_one_da)
display_ntfs_information()
#Call function to extract information of deleted file. Parameters -> cluster2_sector_add, partition_one_da
#CallNTFSFunction else Print NTFS does not exist based on ntfs_exist value

file.close()