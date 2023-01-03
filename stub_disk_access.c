#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <math.h>
#include <stdbool.h>

#define BLOCK_SIZE 512
#define CLUSTER_SIZE 512 * 8
#define START_BLOCK 0

#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN 0x02
#define ATTR_SYSTEM 0x04
#define ATTR_VOLUMN_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20

#define ATTR_LONG_NAME_MASK (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUMN_ID)

uint16_t BPB_BytesPerSec;
uint8_t BPB_SecPerClus;
uint32_t BPB_RootClus;
uint16_t BPB_RsvdSecCnt;
uint8_t BPB_NumFATS;
uint32_t BPB_FATSz32;
uint16_t BPB_RootEntCnt;
uint16_t BPB_FSInfo;  // sector number where FSInfo stored
uint16_t BPB_TotSec16;
uint32_t BPB_TotSec32;
uint16_t BPB_FATSz16;

size_t FirstDataSector;
size_t FirstDataCluster;
size_t RootDirSectors;
size_t DataSec;
size_t CountofClusters;
size_t FirstRootSector;

void * disk;

struct dirent{
    char DIR_Name[11];
    uint8_t DIR_Attr;
    uint8_t DIR_NTRes;
    uint8_t DIR_CrtTimeTenth;
    uint16_t DIR_CrtTime;
    uint16_t DIR_CrtDate;
    uint16_t DIR_LstAccDate;
    uint16_t DIR_FstClusHI;
    uint16_t DIR_WrtTime;
    uint16_t DIR_WrtDate;
    uint16_t DIR_FstClusLO;
    uint32_t DIR_FileSize;
};

void analyze_dir_by_cluster(uint32_t N);

void disk_read_sec(int index, void *dest){
	void *src = (void *)((uint8_t *)disk + index * BLOCK_SIZE);
	memcpy(dest, src, BLOCK_SIZE);
}

void disk_read_cluster(int index, void *dest){
	void *src = (void *)((uint8_t *)disk + index * CLUSTER_SIZE);
	memcpy(dest, src, CLUSTER_SIZE);
}

void disk_write_sec(int index, void *src){
	void *dest = (void *)((uint8_t *)disk + index * BLOCK_SIZE);
	memcpy(dest, src, BLOCK_SIZE);
}

void dump_sector(void *boot_sec, int index){
    // dump sector
    uint8_t *single_sec = (uint8_t*) boot_sec;

    printf("Dumping boot_sec sector %d.\n", index);
    printf("-----------------------------------------------------\n");
    for (size_t i = 0; i < 512 / 16; i++) {
        unsigned char temp_s[17] = {0};
        size_t j = 0;
        while(j < 16){
            if(single_sec[i * 16 + j] >= (uint8_t)32){
                memcpy(temp_s+j, boot_sec + i * 16 + j, 1);
            }else{
                temp_s[j] = '.';
            }
            j ++;
        }
        temp_s[16] = '\0';
        printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x | %s \n",
               single_sec[i * 16 + 0], single_sec[i * 16 + 1], single_sec[i * 16 + 2], single_sec[i * 16 + 3],
               single_sec[i * 16 + 4], single_sec[i * 16 + 5], single_sec[i * 16 + 6], single_sec[i * 16 + 7], single_sec[i * 16 + 8],
               single_sec[i * 16 + 9], single_sec[i * 16 + 10], single_sec[i * 16 + 11], single_sec[i * 16 + 12],
               single_sec[i * 16 + 13], single_sec[i * 16 + 14], single_sec[i * 16 + 15], temp_s);
        // printf("*****\n");
    }
    printf("-----------------------------------------------------\n");
}

void dump_cluster(void *boot_sec, int index){
    // size_t offset = 0;
    // printf("^^^^^^^^^^^^ Dumping cluster %d.\n", index);
    // while(offset < BPB_SecPerClus){
    //     dump_sector(boot_sec + offset*BPB_BytesPerSec, index*8+offset);
    //     offset ++;
    // }
    // printf("^^^^^^^^^^^^ \n");
    // dump sector
    uint8_t *single_sec = (uint8_t*) boot_sec;

    printf("Dumping cluster %d.\n", index);
    printf("-----------------------------------------------------\n");
    for (size_t i = 0; i < CLUSTER_SIZE / 32; i++) {
        unsigned char temp_s[33] = {0};
        size_t j = 0;
        while(j < 32){
            if(single_sec[i * 32 + j] >= (uint8_t)32){
                memcpy(temp_s+j, boot_sec + i * 32 + j, 1);
            }else{
                temp_s[j] = '.';
            }
            j ++;
        }
        temp_s[32] = '\0';
        printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x | %s \n",
               single_sec[i * 32 + 0], single_sec[i * 32 + 1], single_sec[i * 32 + 2], single_sec[i * 32 + 3],
               single_sec[i * 32 + 4], single_sec[i * 32 + 5], single_sec[i * 32 + 6], single_sec[i * 32 + 7], single_sec[i * 32 + 8],
               single_sec[i * 32 + 9], single_sec[i * 32 + 10], single_sec[i * 32 + 11], single_sec[i * 32 + 12],
               single_sec[i * 32 + 13], single_sec[i * 32 + 14], single_sec[i * 32 + 15], single_sec[i * 32 + 16], single_sec[i * 32 + 17], single_sec[i * 32 + 18], single_sec[i * 32 + 19],
               single_sec[i * 32 + 20], single_sec[i * 32 + 21], single_sec[i * 32 + 22], single_sec[i * 32 + 23], single_sec[i * 32 + 24],
               single_sec[i * 32 + 25], single_sec[i * 32 + 26], single_sec[i * 32 + 27], single_sec[i * 32 + 28],
               single_sec[i * 32 + 29], single_sec[i * 32 + 30], single_sec[i * 32 + 31], temp_s);
    }
    printf("-----------------------------------------------------\n");
}

void find_first_sec_of_file(size_t N, size_t *ret){
    *ret = ((N - 2) * BPB_SecPerClus) + FirstDataSector; //calculate the first sector number for root dir (can be used to find the first sector of any cluster N)
}

void find_first_clu_of_file(size_t N, size_t *ret){
    *ret = ((N - 2)) + FirstDataCluster; //calculate the first sector number for root dir (can be used to find the first sector of any cluster N)
}

void read_BPB_sec(void *boot_sec){
    // read a block on the disk
	disk_read_sec(START_BLOCK , boot_sec);
	
	printf("\n\nBoot Sector: \n");
	char OEMName[9] = {0};
	memcpy(OEMName, boot_sec + 3, 8);
	printf(" + OEMName : %s\n", OEMName);
	
	BPB_BytesPerSec = *(uint16_t *)(boot_sec + 11);
	printf(" + BPB_BytesPerSec : %u\n", BPB_BytesPerSec);
	
	BPB_SecPerClus = *(uint8_t *)(boot_sec + 13);
	printf(" + BPB_SecPerClus : %u\n", BPB_SecPerClus);

    BPB_RootClus = *(uint32_t *)(boot_sec + 44);
	printf(" + BPB_RootClus : %u\n", BPB_RootClus);

    BPB_RsvdSecCnt = *(uint16_t *)(boot_sec + 14);
    printf(" + BPB_RsvdSecCnt : %u\n", BPB_RsvdSecCnt);

    BPB_NumFATS = *(uint8_t *)(boot_sec + 16);
	printf(" + BPB_NumFATS : %u\n", BPB_NumFATS);

    BPB_FATSz32 = *(uint32_t *)(boot_sec + 36);
	printf(" + BPB_FATSz32 : %u\n", BPB_FATSz32);

    BPB_RootEntCnt = *(uint16_t *)(boot_sec + 17);
	printf(" + BPB_RootEntCnt : %u\n", BPB_RootEntCnt);

    BPB_FSInfo = *(uint16_t *)(boot_sec + 48);
	printf(" + BPB_FSInfo : %u\n", BPB_FSInfo);

    BPB_TotSec16 = *(uint16_t *)(boot_sec + 19);
	printf(" + BPB_TotSec16 : %u\n", BPB_TotSec16);

    BPB_TotSec32 = *(uint32_t *)(boot_sec + 32);
	printf(" + BPB_TotSec32 : %u\n", BPB_TotSec32);

    BPB_FATSz16 = *(uint16_t *)(boot_sec + 22);
	printf(" + BPB_FATSz16 : %u\n", BPB_FATSz16);

    RootDirSectors = ( (BPB_RootEntCnt * 32) + (BPB_BytesPerSec - 1) ) / BPB_BytesPerSec;
    printf(" + RootDirSectors : %ld\n", RootDirSectors);

    FirstDataSector = BPB_RsvdSecCnt + (BPB_NumFATS * BPB_FATSz32) + RootDirSectors; //calculate the first data sector number
    printf(" + FirstDataSector : %ld\n", FirstDataSector);

    FirstDataCluster = FirstDataSector / BPB_SecPerClus; //calculate the first data cluster number
    printf(" + FirstDataCluster : %ld\n", FirstDataCluster);

    find_first_sec_of_file(BPB_RootClus, &FirstRootSector);
    printf(" + FirstRootSector : %ld\n", FirstRootSector);

    DataSec = BPB_TotSec32 - (BPB_RsvdSecCnt + (BPB_NumFATS * BPB_FATSz32) + RootDirSectors);
    printf(" + DataSec : %ld\n", DataSec);

    CountofClusters = DataSec / BPB_SecPerClus;
    printf(" + CountofClusters : %ld\n", CountofClusters);
    printf("The MAX is : %ld, 0x%lx\n", CountofClusters+FirstDataCluster, CountofClusters+FirstDataCluster);

    assert(BPB_FATSz16 == 0);
    assert(BPB_TotSec16 == 0);
}

void read_FSInfo_sector(void *sec_buf, size_t sec_num){
    // read a block on the disk
	disk_read_sec(sec_num , sec_buf);

    uint32_t FSI_LeadSig = *(uint32_t *)(sec_buf);
	// printf(" + FSI_LeadSig : %u\n", FSI_LeadSig);
    assert(FSI_LeadSig == 0x41615252);

    uint32_t FSI_StrucSig = *(uint32_t *)(sec_buf + 484);
	// printf(" + FSI_StrucSig : %u\n", FSI_StrucSig);
    assert(FSI_StrucSig == 0x61417272);

    uint32_t FSI_Free_Count = *(uint32_t *)(sec_buf + 488); // last known free cluster count
	printf(" + FSI_Free_Count : %u\n", FSI_Free_Count);

    uint32_t FSI_Nxt_Free = *(uint32_t *)(sec_buf + 492); // cluster number of the first available cluster on the volumn
	printf(" + FSI_Nxt_Free : %u\n", FSI_Nxt_Free);

    uint32_t FSI_TrailSig = *(uint32_t *)(sec_buf + 508);
	// printf(" + FSI_TrailSig : %u\n", FSI_TrailSig);
    assert(FSI_TrailSig == 0xaa550000);
}

void read_sector(void *sec_buf, size_t sec_num){
    // read a block on the disk
	disk_read_sec(sec_num , sec_buf);
}

void get_FAT_ent_and_offset(size_t N, size_t *ret_sec_num, size_t *ret_offset){
    size_t FATOffset = N * 4;
    *ret_sec_num = BPB_RsvdSecCnt + (FATOffset / BPB_BytesPerSec); // the sector number of the FAT sector that contains the entry for cluster N in the first FAT
    *ret_offset = FATOffset - ((FATOffset / BPB_BytesPerSec) * BPB_BytesPerSec);
}

uint32_t get_FAT_entry_by_cluster(uint32_t N){
    size_t FAT_ent_sec_num, FAT_ent_offset;
    get_FAT_ent_and_offset(N, &FAT_ent_sec_num, &FAT_ent_offset);

    void *FAT_sec_root_buf = malloc(BLOCK_SIZE);
    read_sector(FAT_sec_root_buf, FAT_ent_sec_num);
    dump_sector(FAT_sec_root_buf, FAT_ent_sec_num);
    uint32_t flag = *(uint32_t *)(FAT_sec_root_buf + FAT_ent_offset);
    free(FAT_sec_root_buf);
    printf(" + FAT_ent_sec_num: %ld, FAT_ent_offset: %ld, flag : %04x\n", FAT_ent_sec_num, FAT_ent_offset, flag);

    return flag;
}

bool check_EoC(uint32_t FAT_entry){

    if( (FAT_entry >= 0xffffff8 && FAT_entry <= 0xffffffe) || FAT_entry == 0xffffffff || FAT_entry >= CountofClusters) {
        printf("IS EoC : %d\n", true);
        return true;
    }
    printf("IS EoC : %d\n", false);
    return false;
}

bool isShortNameEnt(uint8_t dirent_attr){
    if(ATTR_LONG_NAME_MASK && dirent_attr == ATTR_LONG_NAME_MASK){
        return false;
    }
    return true;
}

bool isDirectory(uint8_t dirent_attr){
    if(ATTR_DIRECTORY && dirent_attr == ATTR_DIRECTORY){
        return true;
    }
    return false;
}

bool isFreeEntry(uint8_t first_byte){
    if(first_byte == 0){
        return true;
    }
    return false;
}

void read_file(uint32_t first_cluster_N){

    uint32_t current_N = first_cluster_N;
    size_t current_cluster_num;
    find_first_clu_of_file(current_N, &current_cluster_num);

    while(1){
        // read a cluster
        void *current_cluster_buf = malloc(CLUSTER_SIZE);
        disk_read_cluster(current_cluster_num, current_cluster_buf);
        dump_cluster(current_cluster_buf, current_cluster_num);

        free(current_cluster_buf);

        uint32_t current_FAT_entry = get_FAT_entry_by_cluster(current_N);

        if(check_EoC(current_FAT_entry)){
            goto out;
        }else{
            current_N = current_FAT_entry;
            find_first_clu_of_file(current_N, &current_cluster_num);
        }
    }
out:
    return;
}

bool isCurrentDirEntry(struct dirent *cur_dirent){
    if(cur_dirent->DIR_Name[0] == 0x2e && cur_dirent->DIR_Name[1] == 0x20 && cur_dirent->DIR_Name[2] == 0x20 && cur_dirent->DIR_Name[3] == 0x20 && cur_dirent->DIR_Name[4] == 0x20 && cur_dirent->DIR_Name[5] == 0x20 && cur_dirent->DIR_Name[6] == 0x20 && cur_dirent->DIR_Name[7] == 0x20 && cur_dirent->DIR_Name[8] == 0x20 && cur_dirent->DIR_Name[9] == 0x20 && cur_dirent->DIR_Name[10] == 0x20){
        return true;
    }
    return false;
}

bool isParentDirEntry(struct dirent *cur_dirent){
    if(cur_dirent->DIR_Name[0] == 0x2e && cur_dirent->DIR_Name[1] == 0x2e && cur_dirent->DIR_Name[2] == 0x20 && cur_dirent->DIR_Name[3] == 0x20 && cur_dirent->DIR_Name[4] == 0x20 && cur_dirent->DIR_Name[5] == 0x20 && cur_dirent->DIR_Name[6] == 0x20 && cur_dirent->DIR_Name[7] == 0x20 && cur_dirent->DIR_Name[8] == 0x20 && cur_dirent->DIR_Name[9] == 0x20 && cur_dirent->DIR_Name[10] == 0x20){
        return true;
    }
    return false;
}

void analyze_dir_ent(void *dirent_buf){
    struct dirent *cur_dirent = (struct dirent*) dirent_buf;

    if(!isFreeEntry(cur_dirent->DIR_Name[0])){

        if(isShortNameEnt(cur_dirent->DIR_Attr)){
            char dirrent_name[12] = {'\0'};
            strncpy(dirrent_name, cur_dirent->DIR_Name, 11);

            if(isDirectory(cur_dirent->DIR_Attr)){
                printf(" + Directory : DIR_Name : %s\n", dirrent_name);

                if(!(isCurrentDirEntry(cur_dirent) || isParentDirEntry(cur_dirent))){

                    uint32_t file_data_first_cluster_N = ((uint32_t)cur_dirent->DIR_FstClusHI << 16);
                    file_data_first_cluster_N = file_data_first_cluster_N | (uint32_t)cur_dirent->DIR_FstClusLO;

                    analyze_dir_by_cluster(file_data_first_cluster_N);
                }
            }else{
                printf(" + File : DIR_Name : %s\n", dirrent_name);
                // find the first cluster of the file
                uint32_t file_data_first_cluster_N = ((uint32_t)cur_dirent->DIR_FstClusHI << 16);
                file_data_first_cluster_N = file_data_first_cluster_N | (uint32_t)cur_dirent->DIR_FstClusLO;

                read_file(file_data_first_cluster_N);
            }
        }
    }
    
}

void analyze_dir_by_cluster(uint32_t N){

    uint32_t current_N = N;
    size_t current_cluster_num;
    find_first_clu_of_file(current_N, &current_cluster_num);

    while(1){
        printf("analyze_dir_by_cluster: current_cluster_num : %ld, current_N: %ld\n", current_cluster_num, current_N);
        // read a cluster
        void *current_cluster_buf = malloc(CLUSTER_SIZE);
        disk_read_cluster(current_cluster_num, current_cluster_buf);
        dump_cluster(current_cluster_buf, current_cluster_num);

        // loop over to get each entry
        size_t offset = 0;
        while(offset < CLUSTER_SIZE){
            analyze_dir_ent((void*)(current_cluster_buf + offset));
            offset = offset + 32;
        }

        free(current_cluster_buf);

        uint32_t current_FAT_entry = get_FAT_entry_by_cluster(current_N);

        if(check_EoC(current_FAT_entry)){
            goto out;
        }else{
            current_N = current_FAT_entry;
            find_first_clu_of_file(current_N, &current_cluster_num);
        }
    }
out: 
    return;
}

int main(int argc, char *argv[]) {
    // mount disk
	int disk_fd = open("disk.img" , O_RDWR);
	if(disk_fd == -1 ) { exit(-1); }
	struct stat st;
	fstat(disk_fd, &st);
	
	disk = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, disk_fd, 0);
	if(disk == MAP_FAILED) { exit(1); }
	
    // malloc boot sector
	void *boot_sec = malloc(BLOCK_SIZE);
	if(boot_sec == NULL ) { exit(-1); }
	read_BPB_sec(boot_sec);
    dump_sector(boot_sec, START_BLOCK);
    free(boot_sec);

    // malloc FSInfo sector
	void *fsinfo_sec = malloc(BLOCK_SIZE);
	if(fsinfo_sec == NULL ) { exit(-1); }
	read_FSInfo_sector(fsinfo_sec, BPB_FSInfo);
    dump_sector(fsinfo_sec, BPB_FSInfo);
    free(fsinfo_sec);

    // get entry name in root dir
    analyze_dir_by_cluster(BPB_RootClus);

    // unmount the disk
    int err = munmap(disk, st.st_size);
    if(err == -1) { exit(-1); }
	err = close(disk_fd);
    if(err == -1) { exit(-1); }
	return 0;
}