#include <stdio.h> 
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

int flag = 0;

enum instructions{
    ADD, ADDI, AND, ANDI,
    B, Bcon, BL, BR, 
    CBNZ, CBZ, 
    DUMP, 
    EOR, EORI, 
    HALT, 
    LDUR, LSL, LSR, 
    MUL, 
    ORR, ORRI, 
    PRNL, PRNT, 
    STUR, SUB, SUBI, SUBIS, SUBS
};

typedef struct onn{
  int opcode;
  char* name;
}onn;

onn opcode2name[27] = {
  { 1112, "ADD"},
  { 580, "ADDI"},
  { 1104, "AND"},
  { 584, "ANDI"},
  { 5, "B"},
  { 84, "Bcon"},
  { 37, "BL"},
  { 1712, "BR"},
  { 181, "CBNZ"},
  { 180, "CBZ"},
  { 2046, "DUMP"},
  { 1616, "EOR"},
  { 840, "EORI"},
  { 2047, "HALT"},
  { 1986, "LDUR"},
  { 1691, "LSL"},
  { 1690, "LSR"},
  { 1240, "MUL"},
  { 1360, "ORR"},
  { 712, "ORRI"},
  { 2044, "PRNL"},
  { 2045, "PRNT"},
  { 1984, "STUR"},
  { 1624, "SUB"},
  { 836, "SUBI"},
  { 964, "SUBIS"},
  { 1880, "SUBS"}
};

typedef struct binary_instruction_t{
    int rd;
    int rm;
    int rn;
    int rt;
    int shamt;
    int ALU_immediate;
    int DT_address;
    int BR_address;
    int COND_BR_address;
    int MOV_immediate;
    int opcode11;
    int opcode10;
    int opcode9;
    int opcode8;
    int opcode6;
    int index;
    char assembly[50];
    int instruction;
}binary_instruction_t;

typedef struct machine_state_t{
    int PC;
    int reg[32];
    uint32_t* main;
    uint32_t* stack;
    int flag;
}machine_state_t;

void bin(unsigned n) 
{ 
    /* step 1 */
    if (n > 1) 
        bin(n/2); 
  
    /* step 2 */
    printf("%d", n % 2); 
}

void rInst(uint32_t inst, binary_instruction_t *bi){
    bi->rm = inst>>16;
    bi->rm = bi->rm % 32;
    bi->shamt = inst>>10;
    bi->shamt = bi->shamt % 64;
    bi->rn = inst>>5;
    bi->rn = bi->rn % 32;
    bi->rd = inst % 32;
}

void iInst(uint32_t inst, binary_instruction_t *bi){
    bi->ALU_immediate = inst>>10;
    bi->ALU_immediate = bi->ALU_immediate % 4096;
    bi->rn = inst>>5;
    bi->rn = bi->rn % 32;
    bi->rd = inst % 32;
}

void dInst(uint32_t inst, binary_instruction_t *bi){
    bi->DT_address = inst>>12;
    bi->DT_address = bi->DT_address % 32;
    bi->rn = inst>>5;
    bi->rn = bi->rn % 32;
    bi->rt = inst % 32;
}

void bInst(uint32_t inst, binary_instruction_t *bi){
    bi->BR_address = inst % 67108864;
}

void cbInst(uint32_t inst, binary_instruction_t *bi){
    bi->COND_BR_address = inst>>5;
    bi->COND_BR_address = bi->COND_BR_address % 2097152;
    bi->rt = inst % 32;
}

void iwInst(uint32_t inst, binary_instruction_t *bi){
    bi->MOV_immediate = inst>>5;
    bi->MOV_immediate = bi->MOV_immediate % 65536;
    bi->rd = inst % 32;
}

void decode(uint32_t inst, binary_instruction_t *bi){

    bi->instruction = inst;
    bi->opcode11 = inst>>21;
    bi->opcode10 = inst>>22;
    bi->opcode9 = inst>>23;
    bi->opcode8 = inst>>24;
    bi->opcode6 = inst>>26;

    if (bi->opcode11 == opcode2name[ADD].opcode) {
        bi->index = ADD;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "ADD X%d, X%d, X%d", bi->rd, bi->rn, bi->rm);
    }
    else if (bi->opcode10 == opcode2name[ADDI].opcode) {
        bi->index = ADDI;
	    iInst(inst, bi);
	    sprintf(bi->assembly, "ADDI X%d, X%d, #%d", bi->rd, bi->rn, bi->ALU_immediate);
    }
    else if (bi->opcode11 == opcode2name[AND].opcode) {
        bi->index = AND;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "AND X%d, X%d, X%d", bi->rd, bi->rn, bi->rm);
    }
    else if (bi->opcode10 == opcode2name[ANDI].opcode) {
        bi->index = ANDI;
	    iInst(inst, bi);
	    sprintf(bi->assembly, "ANDI X%d, X%d, #%d", bi->rd, bi->rn, bi->ALU_immediate);
    }
    else if (bi->opcode6 == opcode2name[B].opcode) {
        bi->index = B;
	    bInst(inst, bi);
	    sprintf(bi->assembly, "B %d", bi->BR_address);
    }
    else if (bi->opcode8 == opcode2name[Bcon].opcode) {
        bi->index = B;
	      cbInst(inst, bi);
        if(bi->rt == 0){
            sprintf(bi->assembly, "B.EQ %d", bi->BR_address);
        }
        else if(bi->rt == 1){
            sprintf(bi->assembly, "B.NE %d", bi->BR_address);
        }
        else if(bi->rt == 2){
            sprintf(bi->assembly, "B.HS %d", bi->BR_address);
        }
        else if(bi->rt == 3){
            sprintf(bi->assembly, "B.LO %d", bi->BR_address);
        }
        else if(bi->rt == 4){
            sprintf(bi->assembly, "B.MI %d", bi->BR_address);
        }
        else if(bi->rt == 5){
            sprintf(bi->assembly, "B.PL %d", bi->BR_address);
        }
        else if(bi->rt == 6){
            sprintf(bi->assembly, "B.VS %d", bi->BR_address);
        }
        else if(bi->rt == 7){
            sprintf(bi->assembly, "B.VC %d", bi->BR_address);
        }
        else if(bi->rt == 8){
            sprintf(bi->assembly, "B.HI %d", bi->BR_address);
        }
        else if(bi->rt == 9){
            sprintf(bi->assembly, "B.LS %d", bi->BR_address);
        }
        else if(bi->rt == 10){
            sprintf(bi->assembly, "B.GE %d", bi->BR_address);
        }
        else if(bi->rt == 11){
            sprintf(bi->assembly, "B.LT %d", bi->BR_address);
        }
        else if(bi->rt == 12){
            sprintf(bi->assembly, "B.GT %d", bi->BR_address);
        }
        else if(bi->rt == 13){
            sprintf(bi->assembly, "B.LE %d", bi->BR_address);
        }
    }
    else if (bi->opcode6 == opcode2name[BL].opcode) {
        bi->index = BL;
	    bInst(inst, bi);
	    sprintf(bi->assembly, "BL %d", bi->BR_address);
    }
    else if (bi->opcode11 == opcode2name[BR].opcode) {
        bi->index = BR;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "BR X%d", bi->rt);
    }
    else if (bi->opcode8 == opcode2name[CBNZ].opcode) {
        bi->index = CBNZ;
	    cbInst(inst, bi);
	    sprintf(bi->assembly, "CBNZ X%d, %d", bi->rt, bi->COND_BR_address);
    }
    else if (bi->opcode8 == opcode2name[CBZ].opcode) {
        bi->index = CBZ;
	    cbInst(inst, bi);
	    sprintf(bi->assembly, "CBZ X%d, %d", bi->rt, bi->COND_BR_address);
    }
    else if (bi->opcode11 == opcode2name[DUMP].opcode) {
        bi->index = DUMP;
	    sprintf(bi->assembly, "DUMP");
    }
    else if (bi->opcode11 == opcode2name[EOR].opcode) {
        bi->index = EOR;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "EOR X%d, X%d, X%d", bi->rd, bi->rn, bi->rm);
    }
    else if (bi->opcode10 == opcode2name[EORI].opcode) {
        bi->index = EORI;
	    iInst(inst, bi);
	    sprintf(bi->assembly, "EORI X%d, X%d, #%d", bi->rd, bi->rn, bi->ALU_immediate);
    }
    else if (bi->opcode11 == opcode2name[HALT].opcode) {
        bi->index = HALT;
	    sprintf(bi->assembly, "HALT");
    }
    else if (bi->opcode11 == opcode2name[LDUR].opcode) {
        bi->index = LDUR;
	    dInst(inst, bi);
	    sprintf(bi->assembly, "LDUR X%d, [X%d, #%d]", bi->rt, bi->rn, bi->DT_address);
    }
    else if (bi->opcode11 == opcode2name[LSL].opcode) {
        bi->index = LSL;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "LSL X%d, X%d, #%d", bi->rd, bi->rn, bi->shamt);
    }
    else if (bi->opcode11 == opcode2name[LSR].opcode) {
        bi->index = LSR;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "LSR X%d, X%d, #%d", bi->rd, bi->rn, bi->shamt);
    }
    else if (bi->opcode11 == opcode2name[MUL].opcode) {
        bi->index = MUL;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "MUL X%d, X%d, X%d", bi->rd, bi->rn, bi->rm);
    }
    else if (bi->opcode11 == opcode2name[ORR].opcode) {
        bi->index = ORR;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "ORR X%d, X%d, X%d", bi->rd, bi->rn, bi->rm);
    }
    else if (bi->opcode10 == opcode2name[ORRI].opcode) {
        bi->index = ORRI;
	    iInst(inst, bi);
	    sprintf(bi->assembly, "ORRI X%d, X%d, #%d", bi->rd, bi->rn, bi->ALU_immediate);
    }
    else if (bi->opcode11 == opcode2name[PRNL].opcode) {
        bi->index = PRNL;
	    sprintf(bi->assembly, "PRNL");
    }
    else if (bi->opcode11 == opcode2name[PRNT].opcode) {
        bi->index = PRNT;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "PRNT X%d", bi->rd);
    }
    else if (bi->opcode11 == opcode2name[STUR].opcode) {
        bi->index = STUR;
	    dInst(inst, bi);
	    sprintf(bi->assembly, "STUR X%d, [X%d, #%d]", bi->rt, bi->rn, bi->DT_address);
    }
    else if (bi->opcode11 == opcode2name[SUB].opcode) {
        bi->index = SUB;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "SUB X%d, X%d, X%d", bi->rd, bi->rn, bi->rm);
    }
    else if (bi->opcode10 == opcode2name[SUBI].opcode) {
        bi->index = SUBI;
	    iInst(inst, bi);
	    sprintf(bi->assembly, "SUBI X%d, X%d, #%d", bi->rd, bi->rn, bi->ALU_immediate);
    }
    else if (bi->opcode10 == opcode2name[SUBIS].opcode) {
        bi->index = SUBIS;
	    iInst(inst, bi);
	    sprintf(bi->assembly, "SUBIS X%d, X%d, #%d", bi->rd, bi->rn, bi->ALU_immediate);
    }
    else if (bi->opcode11 == opcode2name[SUBS].opcode) {
        bi->index = SUBS;
	    rInst(inst, bi);
	    sprintf(bi->assembly, "SUBS X%d, X%d, X%d", bi->rd, bi->rn, bi->rm);
    }

    //printf(bi->assembly);
    //printf("\n");
}

char printable_char(uint8_t c)
{
  return isprint(c) ? c : '.';
}

void hexdump(FILE *f, int8_t *start, size_t size)
{
  size_t i;

  for (i = 0; i < size - (size % 16); i += 16) {
    fprintf(f,
            "%08x "
            " %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx "
            " %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx "
            " |%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c|\n",
            (int32_t) i,
            start[i +  0], start[i +  1], start[i +  2], start[i +  3],
            start[i +  4], start[i +  5], start[i +  6], start[i +  7],
            start[i +  8], start[i +  9], start[i + 10], start[i + 11],
            start[i + 12], start[i + 13], start[i + 14], start[i + 15],
            printable_char(start[i +  0]), printable_char(start[i +  1]),
            printable_char(start[i +  2]), printable_char(start[i +  3]),
            printable_char(start[i +  4]), printable_char(start[i +  5]),
            printable_char(start[i +  6]), printable_char(start[i +  7]),
            printable_char(start[i +  8]), printable_char(start[i +  9]),
            printable_char(start[i + 10]), printable_char(start[i + 11]),
            printable_char(start[i + 12]), printable_char(start[i + 13]),
            printable_char(start[i + 14]), printable_char(start[i + 15]));
  }
  fprintf(f, "%08x\n", (int32_t) size);
}

void do_add(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t rm)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] + m->reg[rm];
  }
  m->PC++;
}

void do_addi(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t ALU_immediate)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] + ALU_immediate;
  }
  m->PC++;
}

void do_and(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t rm)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] & m->reg[rm];
  }
  m->PC++;
}

void do_andi(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t ALU_immidiate)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] & ALU_immidiate;
  }
  m->PC++;
}

void do_b(machine_state_t *m, uint32_t BR_address)
{
  m->PC += BR_address;
}

void do_bcon(machine_state_t *m, uint32_t rt, uint32_t BR_address)
{
  if(m->flag == m->reg[rt]){
    m->PC = m->PC + BR_address;
  }
}

void do_bl(machine_state_t *m, uint32_t BR_address)
{
  m->reg[30]=m->PC+4;
  m->PC += BR_address;
}

void do_br(machine_state_t *m, uint32_t rt)
{
  m->PC = m->reg[rt];
}

void do_cbnz(machine_state_t *m, uint32_t rt, uint32_t COND_BR_address)
{
  if(m->reg[rt]!=0){
    m->PC += COND_BR_address;
  }
}

void do_cbz(machine_state_t *m, uint32_t rt, uint32_t COND_BR_address)
{
  if(m->reg[rt]==0){
    m->PC += COND_BR_address;
  }
}

void do_dump(machine_state_t *m)
{
  for(int i = 0; i < 32; i++){
    hexdump(stdout, m->reg[i], 1024+64);
  }
}

void do_eor(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t rm)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] ^ m->reg[rm];
  }
  m->PC++;
}

void do_eori(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t ALU_immidiate)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] ^ ALU_immidiate;
  }
  m->PC++;
}

void do_halt(machine_state_t *m)
{
  do_dump(m);
  exit(0);
}

void do_ldur(machine_state_t *m, uint32_t rt, uint32_t rn, uint32_t DT_address)
{
  if (rt < 28) {
    m->reg[rt] = m->main[m->reg[rn] + DT_address];
  }
}

void do_lsl(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t shamt)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] << shamt;
  }
  m->PC++;
}

void do_lsr(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t shamt)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] >> shamt;
  }
  m->PC++;
}

void do_mul(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t rm)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] * m->reg[rm];
  }
  m->PC++;
}

void do_orr(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t rm)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] | m->reg[rm];
  }
  m->PC++;
}

void do_orri(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t ALU_immidiate)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] | ALU_immidiate;
  }
  m->PC++;
}

void do_prnl(machine_state_t *m)
{
  printf("\n");
  m->PC++;
}

void do_prnt(machine_state_t *m, uint32_t rd)
{
  printf("X%i hex: %04x dec:%i\n", rd, m->reg[rd], m->reg[rd]);
   m->PC++;
}

void do_stur(machine_state_t *m, uint32_t rt, uint32_t rn, uint32_t DT_address)
{
  if (rt < 28) {
    m->main[m->reg[rn] + DT_address] = m->reg[rt];
  }
}

void do_sub(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t rm)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] - m->reg[rm];
  }
  m->PC++;
}

void do_subi(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t ALU_immidiate)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] - ALU_immidiate;
  }
  m->PC++;
}

void do_subis(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t ALU_immidiate)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] - ALU_immidiate;
  }
  int s = m->reg[rd];
  if(s == 0){
    flag = 0;
  }
  else if(s >= 0){
    flag = 1;
  }
  else if(s > 0){
    flag = 2;
  }
  else if(s > 0){
    flag = 3;
  }
  else if(s >= 0){
    flag = 4;
  }
  else if(s <= 0){
    flag = 5;
  }
  else if(s < 0){
    flag = 6;
  }
  else if(s <= 0){
    flag = 7;
  }
  else if(s < 0){
    flag = 8;
  }
  else if(s < 0){
    flag = 9;
  }
  else if(s != 0){
    flag = 10;
  }
  else if(s >= 0){
    flag = 11;
  }
  else if(s = 0){
    flag = 12;
  }
  else if(s = 0){
    flag = 13;
  }
  m->flag = flag;
  m->PC++;

}

void do_subs(machine_state_t *m, uint32_t rd, uint32_t rn, uint32_t rm)
{
  if (rd < 28) {
    m->reg[rd] = m->reg[rn] - m->reg[rm];
  }
  int s = m->reg[rd];
  if(s == 0){
    flag = 0;
  }
  else if(s >= 0){
    flag = 1;
  }
  else if(s > 0){
    flag = 2;
  }
  else if(s > 0){
    flag = 3;
  }
  else if(s >= 0){
    flag = 4;
  }
  else if(s <= 0){
    flag = 5;
  }
  else if(s < 0){
    flag = 6;
  }
  else if(s <= 0){
    flag = 7;
  }
  else if(s < 0){
    flag = 8;
  }
  else if(s < 0){
    flag = 9;
  }
  else if(s != 0){
    flag = 10;
  }
  else if(s >= 0){
    flag = 11;
  }
  else if(s = 0){
    flag = 12;
  }
  else if(s = 0){
    flag = 13;
  }
  m->flag = flag;
  m->PC++;
}

void emulate(binary_instruction_t *bi, int inst_count, machine_state_t *m){
   binary_instruction_t *i;
   while (m->PC != inst_count) {
     i = bi + m->PC;
     switch(i->index) {
     case ADD:
       do_add(m, i->rd, i->rn, i->rm);
       break;
     case ADDI:
       do_addi(m, i->rd, i->rn, i->ALU_immediate);
       break;
     case AND:
       do_and(m, i->rd, i->rn, i->rm);
       break;
     case ANDI:
       do_andi(m, i->rd, i->rn, i->ALU_immediate);
       break;
     case B:
       do_b(m, i->BR_address);
       break;
     case Bcon:
       do_bcon(m, i->rt, i->BR_address);
       break;
     case BL:
       do_bl(m, i->BR_address);
       break;
     case BR:
       do_br(m, i->rt);
       break;
     case CBNZ:
       do_cbnz(m, i->rt, i->COND_BR_address);
       break;
     case CBZ:
       do_cbz(m, i->rt, i->COND_BR_address);
       break;
     case DUMP:
       do_dump(m);
       break;
     case EOR:
       do_eor(m, i->rd, i->rn, i->rm);
       break;
     case EORI:
       do_eori(m, i->rd, i->rn, i->ALU_immediate);
       break;
     case HALT:
       do_halt(m);
       break;
     case LDUR:
       do_ldur(m, i->rt, i->rn, i->DT_address);
       break;
     case LSL:
       do_lsl(m, i->rd, i->rn, i->shamt);
       break;
     case LSR:
       do_lsr(m, i->rd, i->rn, i->shamt);
       break;
     case MUL:
       do_mul(m, i->rd, i->rn, i->rm);
       break;
     case ORR:
       do_orr(m, i->rd, i->rn, i->rm);
       break;
     case ORRI:
       do_orri(m, i->rd, i->rn, i->ALU_immediate);
       break;
     case PRNL:
       do_prnl(m);
       break;
     case PRNT:
       do_prnt(m, i->rd);
       break;
     case STUR:
       do_stur(m, i->rt, i->rn, i->DT_address);
       break;
     case SUB:
       do_sub(m, i->rd, i->rn, i->rm);
       break;
     case SUBI:
       do_subi(m, i->rd, i->rn, i->ALU_immediate);
       break;
     case SUBIS:
       do_subis(m, i->rd, i->rn, i->ALU_immediate);
       break;
     case SUBS:
       do_subs(m, i->rd, i->rn, i->rm);
       break;
     }
   }
}

int main(int argc, char *argv[]){
    int binary = 1;
    FILE* fd;
    uint32_t *program;
    uint32_t *bprogram;
    machine_state_t m;
    struct stat buf;
    
    if (binary) {
        fd = open(argv[1], O_RDONLY);
        fstat(fd, &buf);
        program = mmap(NULL, buf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        bprogram = calloc(buf.st_size / 4, sizeof (*bprogram));
        m.main = calloc(1024, sizeof(uint32_t));
        m.stack = calloc(64, sizeof(uint32_t));
        memset(m.main, 0, 1024);
        memset(m.stack, 0, 64);

        for (int i = 0; i < (buf.st_size / 4); i++) {
            program[i] = be32toh(program[i]);
            decode(program[i], bprogram + i);
        }
        emulate(bprogram, buf.st_size / 4, &m);
        return 0;
    }
}
