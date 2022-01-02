# ForensicsTool

This assignment involves the development of a basic file system forensic tool. The phase 1 
submittable includes the extraction of valuable information found in the Master Boot Record 
(MBR) of a disk drive. The tool displaysthe number of partitions on the disk and for each 
partition displaysthe file system type, start sector, and the size of the partition. 

Phase 2 will include the completion of the tool. For the first partition only, the tool will 
display the number of sectors per cluster, the size of the FAT area, the size of the Root 
Directory, and the sector address of Cluster #2. For the first deleted file found on the 
volume’s root directory, the tool will display the name and size of that file, as well as the first
16 characters of the contents of the file. For this assignment, the first partition of the disk 
drive will always be of FAT-16 type. 

The final requirement involves the examination of NTFS file partition volume. The tool shall 
display the number of bytes per sector for this NTFS volume and the number of sectors per 
cluster for this NTFS volume. Furthermore, the tool will profile information for the $MFT 
file record. This includes its sector address, and the type and length of the first two attributes
in the record

python PartitionInfo.py diskimage.dd
