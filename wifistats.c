/*
   CITS2002 Project 1 2017
   Name(s):             Alexander Rafferty
   Student number(s):   21712241
   Date:                date-of-submission
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <memory.h>
#include <ctype.h>

#define MAC_LENGTH 6
#define OUI_LENGTH 3

/** Formats a MAC address or OUI represented as raw bytes
    into a human-readable string.
    Assumes that the output buffer is large enough to hold the result.
**/
void format_mac(char *mac, int len, char *out)
{
  for (int i = 0; i < len - 1; i++) {
    sprintf(out + (i * 3), "%02x:", (unsigned char)mac[i]);
  }
  sprintf(out + ((len - 1) * 3), "%02x", (unsigned char)mac[len - 1]);
}

/** Calls /usr/bin/sort to print the packet statistics in sorted order
**/
void print_sorted(char (*mac_list)[MAC_LENGTH], int *bytes_list, int num_macs, char (*ouis)[3], char **vendors, int num_vendors)
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
    char *args[] = { "sort", "-t", "\t", "-k", "2,2nr", "-k", "1,1", NULL };
    if (ouis != NULL) {
      // Sorts by bytes (3rd column) descending, then by vendor name (2nd column) ascending
      args[3] = "3,3";
      args[6] = "2,2";
    }
    execv("/usr/bin/sort", args);
    _exit(errno);
  } else {
    // Close unneeded pipes
    close(pd[0]);
    close(pd[3]);
    // Prints the unsorted output of the program
    int total_unknown_bytes = 0;
    for (int i=0; i<num_macs; i++) {
      char *macb = mac_list[i];
      if (ouis == NULL) {
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
        char *vendor = NULL;
        for (int vind = 0; vind < num_vendors; vind++) {
          if (memcmp(ouis[vind], macb, OUI_LENGTH) == 0) {
            vendor = vendors[vind];
            break;
          }
        }
        if (vendor == NULL) {
          total_unknown_bytes += bytes;
          continue;
        }
        char line[255];
        sprintf(line, "%s\t%s\t%i\n", mac, vendor, bytes);
        write(pd[1], line, strlen(line));
      }
    }
    if (total_unknown_bytes > 0) {
      char line[255];
      sprintf(line, "??:??:??\tUNKNOWN-VENDOR\t%i\n", total_unknown_bytes);
      write(pd[1], line, strlen(line));
    }
    // Finished printing
    close(pd[1]);
    // Wait for sort process to terminate
    int status;
    wait(&status);
    // Read sorted results and output to stdout
    char buffer[10000];
    int bytesRead;
    while ((bytesRead = read(pd[2], buffer, 9999)) > 0) {
      buffer[bytesRead] = '\0';
      printf("%s", buffer);
    }
    close(pd[2]);
  }
}

/** Reads the packet file and creates an array of mac addresses
    with a corresponding array containing total bytes sent/received
    from that address according to the t_or_r parameter.
    If group_by_vendor is true, then results are aggregated according
    to OUI address rather than the entire MAC address.
**/
int read_packets_file(char *filename, char t_or_r, char (*mac_list)[MAC_LENGTH], int *bytes_list, bool group_by_vendor)
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
    // Get the MAC addresses and convert to raw bytes
    char *mac_t = fields[1];
    char *mac_r = fields[2];
    char macb_t[MAC_LENGTH], macb_r[MAC_LENGTH];
    bool t_broadcast = true, r_broadcast = true;
    for (int i = 0; i < MAC_LENGTH; i++) {
      macb_t[i] = strtol(mac_t + (i * 3), NULL, 16);
      macb_r[i] = strtol(mac_r + (i * 3), NULL, 16);
      if (macb_t[i] != ~0) t_broadcast = false;
      if (macb_r[i] != ~0) r_broadcast = false;
    }
    // Ignore broadcasted packets
    if (t_broadcast || r_broadcast) {
      continue;
    }
    // Select the right MAC address
    char *macb;
    if (t_or_r == 't') {
      macb = macb_t;
    } else {
      macb = macb_r;
    }
    // If grouping by vendor, ignore non-OUI bytes
    if (group_by_vendor) {
      macb[3] = 0;
      macb[4] = 0;
      macb[5] = 0;
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

/** Reads the OUI file and creates an array of OUIs with
    a corresponding array of vendor names
**/
int read_oui_file(char *filename, char (**ouis_out)[OUI_LENGTH], char ***vendors_out)
{
  // Create a buffer with an initial size
  int size = 0;
  int capacity = 1024;
  char (*ouis)[OUI_LENGTH] = malloc(capacity * OUI_LENGTH * sizeof(char));
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
    // Convert the MAC oui to raw bytes
    char *mac = fields[0];
    char macb[OUI_LENGTH];
    for (int i = 0; i < OUI_LENGTH; i++) {
      macb[i] = strtol(mac + (i * OUI_LENGTH), NULL, 16);
    }
    // Insert the new MAC oui
    if (size >= capacity) {
      // Grow the buffer
      capacity += 1024;
      char (*new_ouis)[3] = malloc(capacity * OUI_LENGTH * sizeof(char));
      char **new_vendors = malloc(capacity * sizeof(char*));
      memcpy(new_ouis, ouis, size * OUI_LENGTH);
      memcpy(new_vendors, vendors, size * sizeof(char*));
      free(ouis);
      free(vendors);
      ouis = new_ouis;
      vendors = new_vendors;
    }
    memcpy(ouis[size], macb, OUI_LENGTH);
    int vendor_len = strlen(vendor) + 1;
    vendors[size] = malloc(vendor_len);
    memcpy(vendors[size], vendor, vendor_len);
    size++;
  }
  // Close the file
  fclose(fp);
  // Return the data and number of vendors
  *ouis_out = ouis;
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
      t_or_r = tolower(argv[1][0]);
      if ((t_or_r != 't') && (t_or_r != 'r')) {
        printf("First argument must be 't' or 'r'.\n");
        exit(EXIT_FAILURE);
      }
      break;
    default:
      printf("Wrong number of arguments.\n");
      exit(EXIT_FAILURE);
  }
  // Create buffers for storing data
  int num_packets, num_vendors;
  char mac_list[1024][MAC_LENGTH];
  int bytes_list[1024];
  char (*ouis)[OUI_LENGTH] = NULL;
  char **vendors = NULL;
  // Parse the OUI file if supplied
  if (use_oui) {
    num_vendors = read_oui_file(oui_fn, &ouis, &vendors);
  }
  // Parse the packet file
  num_packets = read_packets_file(packets_fn, t_or_r, mac_list, bytes_list, use_oui);
  // Print the results in sorted order
  print_sorted(mac_list, bytes_list, num_packets, ouis, vendors, num_vendors);
  return 0;
}