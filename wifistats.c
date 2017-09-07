#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <memory.h>

#define MAC_LENGTH 6
#define OUI_LENGTH 3

/* TODO:

  - Better distinguish between MAC strings and raw bytes in var names
  - Sort the output
  - Replace "MAC prefix" with "OUI"
  - Replace memcpy for MACs with custom function

*/

/* Finds the index of the OUI, or returns -1 if not found */
int find_prefix_ind(unsigned char (*haystack)[OUI_LENGTH], int size, unsigned char needle[3])
{
  // If size is small, perform linear search
  if (size < 10) {
    for (int i = 0; i < size; i++) {
      int cmp = memcmp(haystack[i], needle, OUI_LENGTH);
      if (cmp > 0) return -1;
      if (cmp == 0) return i;
    }
    return -1;
  } else {
    int middle = size / 2;
    int comp = memcmp(haystack[middle], needle, OUI_LENGTH);
    if (comp == 0) {
      return middle;
    }
    if (comp < 0) {
      int m1 = middle + 1;
      int ind = find_prefix_ind(haystack + m1, size - m1, needle);
      if (ind == -1) {
        return -1;
      } else {
        return ind + m1;
      }
    } else {
      return find_prefix_ind(haystack, middle, needle);
    }
  }
}

void format_mac(unsigned char *mac, int len, char *out)
{
  for (int i = 0; i < len - 1; i++) {
    sprintf(out + (i * 3), "%02x:", mac[i]);
  }
  sprintf(out + ((len - 1) * 3), "%02x", mac[len - 1]);
}

void print_sorted(unsigned char (*mac_list)[MAC_LENGTH], int *bytes_list, int list_len, unsigned char (*prefixes)[3], char **vendors, int num_vendors)
{
  // Create the pipes to communicate between parent and child process
  int pd[4];
  if (pipe(pd) == -1 || pipe(pd + 2) == -1) {
    exit(EXIT_FAILURE);
  }
  // Fork the process to run sort
  int pid = fork();
  if (pid == -1) exit(EXIT_FAILURE);
  if (pid == 0) {
    // Connect stdin and stdout to pipes and run sort
    close(pd[1]);
    close(pd[2]);
    dup2(pd[0], STDIN_FILENO);
    dup2(pd[3], STDOUT_FILENO);
    // Sorts by bytes (2nd column) descending, then by mac address (1st column) ascending
    char *args[] = { "sort", "-t", "\t", "-k", "2,2", "-nr", "-k", "1,1", NULL };
    if (prefixes != NULL) {
      // Sorts by bytes (3rd column) descending, then by vendor name (2nd column) ascending
      args[4] = "3,3";
      args[7] = "2,2";
    }
    execv("/usr/bin/sort", args);
    _exit(errno);
  } else {
    // Close unneeded pipes
    close(pd[0]);
    close(pd[3]);
    // Iterate over list and print results into sort
    for (int i=0; i<list_len; i++) {
      unsigned char *macb = mac_list[i];
      if (prefixes == NULL) {
        char mac[20];
        format_mac(macb, MAC_LENGTH, mac);
        int bytes = bytes_list[i];
        char line[255];
        sprintf(line, "%s\t%i\n", mac, bytes);
        write(pd[1], line, strlen(line));
      } else {
        char mac[20];
        format_mac(macb, OUI_LENGTH, mac);
        int bytes = bytes_list[i];
        char *vendor = "UNKOWN-VENDOR";
        for (int vind = 0; vind < num_vendors; vind++) {
          if (memcmp(prefixes[vind], macb, OUI_LENGTH) == 0) {
            vendor = vendors[vind];
            break;
          }
        }
        char line[255];
        sprintf(line, "%s\t%s\t%i\n", mac, vendor, bytes);
        write(pd[1], line, strlen(line));
      }
    }
    // Finished printing
    close(pd[1]);
    // Wait for sort process to terminate
    int status;
    wait(&status);
    // Read sorted results and output to stdout
    char buffer[8192];
    buffer[8191] = '\0';
    while (read(pd[2], buffer, 8191) > 0) {
      printf("%s", buffer);
    }
    close(pd[2]);
  }
}

int read_packets_file(char *filename, char t_or_r, unsigned char (*mac_list)[MAC_LENGTH], int *bytes_list, bool group_by_vendor)
{
  // Buffers for storing results
  int list_len = 0;
  // Open the packets file
  FILE *fp;
  fp = fopen(filename, "r");
  if (fp == NULL) {
    printf("Cannot open %s.\n", filename);
    exit(EXIT_FAILURE);
  }
  // Read in each line from the file
  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    // Seperate the fields of the file
    char *fields[4];
    fields[0] = line;
    int field = 0;
    for (char *c = line; *c != '\n'; c++) {
      if (*c != '\t') continue;
      *c = '\0';
      field++;
      fields[field] = c + 1;
    }
    // Get the MAC address and convert to raw bytes
    char *mac = fields[1];
    if (t_or_r == 'r') {
      mac = fields[2];
    }
    unsigned char macb[MAC_LENGTH];
    bool is_broadcast = true;
    for (int i = 0; i < MAC_LENGTH; i++) {
      macb[i] = strtol(mac + (i * 3), NULL, 16);
      if (macb[i] != 255) is_broadcast = false;
    }
    if (group_by_vendor) {
      // If grouping by vendor, ignore non-OUI bytes
      macb[3] = 0;
      macb[4] = 0;
      macb[5] = 0;
    }
    // Ignore broadcasted packets
    if (is_broadcast) {
      continue;
    }
    // Get the number of bytes
    int bytes = atoi(fields[3]);
    // Find mac address in list
    int ind = 0;
    for (; ind < list_len; ind++) {
      if (memcmp(macb, mac_list[ind], MAC_LENGTH) == 0) break;
    }
    if (ind == list_len) {
      // No entry found, create a new one
      memcpy(mac_list[ind], macb, MAC_LENGTH);
      bytes_list[ind] = 0;
      list_len++;
    }
    // Add bytes to running total
    bytes_list[ind] += bytes;
  }
  // Close the file
  fclose(fp);
  // Return the length of the list
  return list_len;
}

int read_oui_file(char *filename, unsigned char (**prefixes_out)[OUI_LENGTH], char ***vendors_out)
{
  // Create a buffer with an initial size
  int size = 0;
  int capacity = 1024;
  unsigned char (*prefixes)[OUI_LENGTH] = malloc(capacity * OUI_LENGTH * sizeof(unsigned char));
  char **vendors = malloc(capacity * sizeof(char*));
  // Open the file
  FILE *fp;
  fp = fopen(filename, "r");
  if (fp == NULL) {
    printf("Cannot open %s.\n", filename);
    exit(EXIT_FAILURE);
  }
  // Read in each line from the file
  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    // Seperate the fields of the file
    char *fields[2];
    fields[0] = line;
    int field = 0;
    for (char *c = line; *c != '\n'; c++) {
      if (*c != '\t') continue;
      *c = '\0';
      field++;
      fields[field] = c + 1;
    }
    // Get the vendor name, and remove trailing newline
    char *vendor = fields[1];
    vendor[strlen(vendor) - 1] = '\0';
    // Convert the MAC prefix to raw bytes
    char *mac = fields[0];
    unsigned char macb[OUI_LENGTH];
    for (int i = 0; i < OUI_LENGTH; i++) {
      macb[i] = strtol(mac + (i * OUI_LENGTH), NULL, 16);
    }
    // Insert the new MAC prefix
    if (size >= capacity) {
      // Grow the buffer
      capacity += 1024;
      unsigned char (*new_prefixes)[3] = malloc(capacity * OUI_LENGTH * sizeof(unsigned char));
      char **new_vendors = malloc(capacity * sizeof(char*));
      memcpy(new_prefixes, prefixes, size * OUI_LENGTH * sizeof(unsigned char));
      memcpy(new_vendors, vendors, size * sizeof(char*));
      free(prefixes);
      free(vendors);
      prefixes = new_prefixes;
      vendors = new_vendors;
    }
    memcpy(prefixes[size], macb, OUI_LENGTH);
    int vendor_len = strlen(vendor) + 1;
    vendors[size] = malloc(vendor_len * sizeof(char));
    memcpy(vendors[size], vendor, vendor_len * sizeof(char));
    size++;
  }
  // Close the file
  fclose(fp);
  // Sort by vendor prefix
  // sort_vendors_by_oui(prefixes, vendors, size);
  // Return the data and number of vendors
  *prefixes_out = prefixes;
  *vendors_out = vendors;
  return size;
}

int main(int argc, char *argv[])
{
  char t_or_r;
  char *packets_fn;
  char *oui_fn;
  bool use_oui = false;
  // Check and read in command line arguments
  switch(argc) {
    case 4:
    use_oui = true;
    oui_fn = argv[3];
    case 3:
    packets_fn = argv[2];
    t_or_r = argv[1][0];
    break;
    default:
    printf("Wrong number of arguments.\n");
    exit(EXIT_FAILURE);
  }
  // Create buffers for storing data
  int num_packets, num_vendors;
  unsigned char mac_list[1024][MAC_LENGTH];
  int bytes_list[1024];
  unsigned char (*prefixes)[OUI_LENGTH] = NULL;
  char **vendors = NULL;
  // Parse the OUI file if supplied
  if (use_oui) {
    num_vendors = read_oui_file(oui_fn, &prefixes, &vendors);
  }
  // Parse the packet file
  num_packets = read_packets_file(packets_fn, t_or_r, mac_list, bytes_list, use_oui);
  // Print the results in sorted order
  print_sorted(mac_list, bytes_list, num_packets, prefixes, vendors, num_vendors);
  return 0;
}