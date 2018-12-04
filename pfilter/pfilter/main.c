//
//  main.c
//  pfilter
//
//  Created by Christian Velasco on 2018-11-30.
//  Copyright © 2018 Christian Velasco. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>



//Struct with relevant information for AS4
typedef enum{
    Allowed,
    Denied,
    Undefined
} permisions;

typedef enum{
    UDP,
    TCP,
    UNKNOWN
}transportLayerProtocol;

typedef enum{
    HasPortWildStar,
    NoPortWildStar
}portWildStar;

struct packetInfo{
    uint16_t sPort;
    uint16_t dPort;
    uint32_t sIP;
    uint32_t dIP;
    transportLayerProtocol layerProtocol;
};

//Rules Struct
typedef struct rules{
    permisions permision;
    uint8_t sourceIP_wild_star_location;
    uint8_t sPortstar;
    uint8_t destinationIP_wild_star_location;
    uint8_t dPortstar;
    struct packetInfo packetrules;
    struct rules *next;
    
    
} frules;

/* Function: packetInfo
 * @param: const char* file -> name of the rawPacket file
 * info:
 *      Reads the rawPacket, and creates a struct packetInfo which the
 *      revelant information for the assignment
 *
 */
struct packetInfo getPacketInfo(const char* file){
    
    //Open file
    FILE *packet_fp = fopen(file,"rb");
    //Fail to open packet file
    if(packet_fp == NULL)
        exit(EXIT_FAILURE);
        
        //Get size of file
        fseek(packet_fp, 0, SEEK_END);
        size_t fsize = ftell(packet_fp);
        fseek(packet_fp, 0, SEEK_SET); //Move back to top
        
        //Create buffer & //Read Raw packet file
        char* buffer = malloc(fsize);
        fread(buffer,fsize,1, packet_fp);
        
        //get IP header from buffer
        struct ip * iphd = (struct ip *) buffer;
        struct packetInfo packet = {};
        
        //store IP address in struct
        packet.sIP = iphd->ip_src.s_addr;
        packet.dIP = iphd->ip_dst.s_addr;
        
        //Check for Protocol Type, and selected the correct one
        //and store the information in the struct
        if(iphd->ip_p == IPPROTO_TCP){
            struct tcphdr * tcphd = (struct tcphdr *) (sizeof(struct ip) + buffer);
            packet.sPort = htons(tcphd->th_sport);
            packet.dPort = htons(tcphd->th_dport);
            packet.layerProtocol = TCP;
            //clear up
            
        }else if(iphd->ip_p == IPPROTO_UDP){
            struct udphdr * udpphd = (struct udphdr *) (sizeof(struct ip) + buffer);
            packet.sPort = htons(udpphd->uh_sport);
            packet.dPort = htons(udpphd->uh_dport);
            packet.layerProtocol = UDP ;
            
            //clean up
        }//The Packet privided follows a protocol that is neither TCP or UDP
        else{
            printf("<unspecified>\n");
            exit(EXIT_FAILURE);
        }
    
    //Clean Up
    fclose(packet_fp); //Close file
    free(buffer);
    
    //return struct
    return packet;
}

/* Function: push
 * @param: frules *head -> head of the permisions linked-list
 * @paramt: frules *newRule -> a frule struct with a rule
 * Info:
 *      Adds new rule to the end of the linked list
 */
void push(frules *head, frules *newRule){
    //IF Head is empty
    frules * current = head;
    //traverse to end of the list
    while(current->next != NULL){
        current = current->next;
    }
    //Copy all Information of struct
    current->next = malloc(sizeof(frules));
    current->next->permision = newRule->permision;
    current->next->packetrules.layerProtocol = newRule->packetrules.layerProtocol;
    current->next->packetrules.dIP = newRule->packetrules.dIP;
    current->next->packetrules.dPort = newRule->packetrules.dPort;
    current->next->packetrules.sIP = newRule->packetrules.sIP;
    current->next->packetrules.sPort = newRule->packetrules.sPort;
    current->next->destinationIP_wild_star_location = newRule->destinationIP_wild_star_location;
    current->next->sourceIP_wild_star_location = newRule->sourceIP_wild_star_location;
    current->next->sPortstar = newRule->sPortstar;
    current->next->dPortstar = newRule->dPortstar; 
    current->next->next = NULL;
    

}

/* Function: getIP_Wild_Star_Position
 * @param: char * ipString -> an IP address in string form (i.e. "10.10.10.10")
 * Info:
 *      This is a helper function which check which position the Wild star in the in IP address
 *      - This number is used for shifting later on, to compare the IP address
 */
uint8_t getIP_Wild_Star_Position(char * ipString){
    int starLocation = 9;
    char star = '*';
    int dots = 0;
    for(int i = 0; ipString[i] != '\0'; i++) {
        if(dots == 0 && ipString[i] == star){
            starLocation = 4;
            break;
        }
        if(dots == 1 && ipString[i] == star){
            starLocation = 3;
            break;
        }
        if(dots == 2 && ipString[i] == star ){
            starLocation = 2;
            break;
        }
        if(ipString[i] == '.'){
            dots++;
        }
    }
    if(starLocation == 9){
        starLocation = 1;
    }
    
    return starLocation;
}


void printStructRule(frules *rule){

    char* permision;
    char* protocol;
    if(rule->permision == Allowed){
        permision = "Allow";
    }else if( rule->permision == Denied){
         permision = "Deny";
    }else{
        permision = "Undefined";
    }
    if(rule->packetrules.layerProtocol == TCP){
        protocol = "TCP";
    }else if( rule->packetrules.layerProtocol == UDP){
        protocol = "UDP";
    }else{
        protocol = "UNKOWN";
    }
    printf("RULE\n");
    printf("Permision:        %s\n", permision);
    printf("Protocol:         %s\n", protocol);
    printf("Source IP:        %x\n", rule->packetrules.sIP);
    printf("Source Port:      %d\n", rule->packetrules.sPort);
    printf("Destination IP:   %x\n", rule->packetrules.dIP);
    printf("Destination Port: %d\n", rule->packetrules.dPort);
    printf("WILD START INFO\n");
    printf("sIP Wild-star: %d\n", rule->sourceIP_wild_star_location);
    printf("sPort Wild-start: %d\n", rule->sPortstar);
    printf("dIP Wild-start %d\n", rule->destinationIP_wild_star_location);
    printf("dPort WildStart %d\n", rule->dPortstar);
    
}

/* Function: getRules
 * @param: const char * file -> Name of file which contains the permision rules rules
 * @param: frules *head -> head pointer to the linked list, used to store the permision rules
 * Info:
 *      This functions reads a permision files, and stores all the rules in a linked list.
 */
void getRules (const char *file, frules *head){

    //Open file
    FILE *rules_f = fopen(file,"rb");
    char * line = NULL;
    size_t lineSize = 0;
    ssize_t read;
    
    //Fail to open file
    if(rules_f == NULL){
        exit(EXIT_FAILURE);
    }
    
    frules *current = NULL;
    
    
    /* Read through Permision file*/
    while((read = getline(&line, &lineSize,rules_f)) != -1){
        
        current = malloc(sizeof(frules));
        //GET INITIAL-TOKEN
        char *token = strtok(line, "\n ");
        /*
        IF INITIAL TOKEN == \n *space, it means we reach and empty line
        will assume this is the end of a file */
        if( token == NULL){
            current = NULL;
            break;
        }
        /* GET Permisions  */
        if(strcmp("allow",token) == 0 ){
            current->permision = Allowed;
        }else if(strcmp("deny",token) == 0 ){
            current->permision = Denied;
        }else{
            current->permision = Undefined;
        }
        /* GET Protocol  */
        token = strtok(NULL," ");
        if(strcmp("tcp",token) == 0){
            current->packetrules.layerProtocol = TCP;
        }else if(strcmp("udp",token) == 0){
            current->packetrules.layerProtocol = UDP;
        }else{
            current->packetrules.layerProtocol = UNKNOWN;
        }

        /* GET Source IP address: Check if there is a wild star '*'. */
        token = strtok(NULL,":");
        char* s = strchr(token, '*');                              //CHECK if there is a '*'
        if( s == NULL){                                            //There is no '*'
            current->packetrules.sIP = inet_addr(token);
            current->sourceIP_wild_star_location = 9; 
            
        }else{                                                     //There is a '*'
            current->sourceIP_wild_star_location = getIP_Wild_Star_Position(token);
            *s = '0';
            current->packetrules.sIP = inet_addr(token);
        }
        /* GET Source Port number, also checks if the is a Wild Star '*' */
        token = strtok(NULL, " ");
        s = strchr(token, '*');
        if(s == NULL){
            current->sPortstar = 0;
            current->packetrules.sPort = (uint16_t) strtoul(token, NULL, 10);
        }else{
            current->sPortstar = 1;
            current->packetrules.sPort = 0;
            
        }
         /* GET Destination IP address: Check if there is a wild star '*'. */
        token = strtok(NULL, " ");
        token = strtok(NULL,":");
        s = strchr(token, '*');
        if(s == NULL){
            current->packetrules.dIP = inet_addr(token);
            current->destinationIP_wild_star_location = 9;
        }else{
            current->destinationIP_wild_star_location = getIP_Wild_Star_Position(token);
            *s = '0';
            current->packetrules.dIP =inet_addr(token);
        }
        
        /* GET Destination Port number, also checks if the is a Wild Star '*' */
        token = strtok(NULL, " ");
        s = strchr(token, '*');
        if(s == NULL){
            current->dPortstar = 0;
            current->packetrules.dPort = (uint16_t) strtoul(token, NULL, 10);
        }else{
            current->dPortstar = 1;
            current->packetrules.dPort = 0; 
        }
        //PUSH NEW RULE INTO LIST
        push(head, current);
        free(current);
    }

    //clean up
    fclose(rules_f);
    free(line);
    //free(current);
}

/* Function: isPacketApprove
 * @param: struct packetInfo packet -> struct containting the IPs,Ports and Protocols from the rawPacket
 * @param: frules *head -> head of the linked-list of the permision rules
 *Info:
 *      This function reads through the linked-list of permisions looking for a rule
 *      that holds for the rawpacket. It returns an answer base on the rules.
 *      0 - deny
 *      1 - allow
 *      2 - unspecified
 */
uint8_t isPacketApprove(struct packetInfo packet, frules *head){
    
    frules *current = head;
    int sPortPass = 0;
    int dPortPass = 0;
    int sIPPass = 0;
    int dIPPass = 0;
    int protocol = 0;
    
    while(current != NULL){
        
        /* Check if using the same protocol*/
        if(current->packetrules.layerProtocol == packet.layerProtocol){
            protocol = 1;
        }
        /*Check if IP and Port addresses Match */
        if(current->sourceIP_wild_star_location == 9){
            if(current->packetrules.sIP == packet.sIP){
                sIPPass = 1;
            }
        }else{ /* There is a Wild-star, Thus we are going to only check for the initial */
            if(current->sourceIP_wild_star_location == 4){
                sIPPass = 1;
            }else if( (current->packetrules.sIP << (8*current->sourceIP_wild_star_location)) == (packet.sIP <<(8*current->sourceIP_wild_star_location))){
                sIPPass = 1;
            }
        }
        /* CHECK Source Port */
        //Check if there is a wild-star
        if(current->sPortstar == 0){
            if(current->packetrules.sPort == packet.sPort){
                sPortPass = 1;
            }
        }else{
            sPortPass = 1;
        }
        /*CHECK Destination IP */
        //Check if there is a wild-star
        if(current->destinationIP_wild_star_location == 9){
            if(current->packetrules.dIP == packet.dIP){
                dIPPass = 1;
            }
        }else{ /* There is a Wild-star, Thus we are going to only check for the initial */
               //((packet.dIP>> (8*current->destinationIP_wild_star_location)) & 0xFF) == ;
            if(current->destinationIP_wild_star_location == 4){
                dIPPass = 1;
            }else if( (current->packetrules.dIP << (8*current->destinationIP_wild_star_location)) == (packet.dIP <<(8*current->destinationIP_wild_star_location) )){
                dIPPass = 1;
            }
        }
        /* CHECK Destination Port */
        //Check if there is a wild-star
        if(current->dPortstar == 0){
            if(current->packetrules.dPort == packet.dPort){
                dPortPass = 1;
            }
        }else{
            dPortPass = 1;
        }
        
        /*Check if rules Information matches*/
        if((sPortPass+dPortPass+dIPPass+sIPPass+protocol) == 5){
            /*Check If use the same Protocol */
            if(current->permision == Allowed){
                //Return 1 to declare permision is allowed
                return 1;
            }else{
                //return 0 to declare permision is deny
                return 0;
            }
        }
        //Move to next
        current = current->next;
    }
    //Return 2, to declare permision is undefiend
    return 2;
}

int main(int argc, const char * argv[]) {
    //Check Arguments are correct
    if( argc != 3){
        return -1;
    }
    //GET rules
    frules *head;
    head = malloc(sizeof(frules));
    head->permision = Undefined;
    head->next = NULL;
    //Get number
    getRules(argv[1], head);
    
    //GET Packet Information
    struct packetInfo packet = getPacketInfo(argv[2]);
    
    //Check if we allowed the raw package
    uint8_t permision =  isPacketApprove(packet, head);

    if(permision == 0){
        printf("deny\n");
    }else if(permision == 1){
        printf("allow\n");
    }else{
        printf("unspecified\n");
    }
    return 0;
}
