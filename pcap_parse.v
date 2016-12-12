`timescale 1ns / 1ps
`define NULL 0


// Engineer:    Jose Fernando Zazo
// Description:
//    Utility to replay a packets from a pcap file over a 64-bit for use in network test benches.
//  Based on the original work of Chris Shucksmith (https://github.com/shuckc/)
// Modify by Mario Ruiz
// Mode allows to user send for AXI-Stream header of pcap file
// Mode 0, only data is send
// Mode 1, size of packets and data are send
// Mode 2, timestamp, size of packets and data are send


`define abs(a) ((a) < 0) ? -(a) : (a)

module pcap_parse
    #(
        parameter pcap_filename         = "none",
        parameter use_custom_ifg        = "TRUE",   
        parameter default_ifg           = 6,
        parameter default_mode          = 0,
        parameter CLOCK_FREQ_HZ         = 322265625,
        parameter AXIS_WIDTH            = 512,
        parameter BRAM_DEPTH            = 8,
        parameter HEADER_SIZE_LENGTH    = 16
    ) (
        input  wire                         clk,       //       .clk
        input                               reset,

        output reg  [AXIS_WIDTH-1:0]        data,      //       .data
        output reg  [(AXIS_WIDTH/8)-1:0]    keep,      //       .keep
        input  wire                         ready,     //       .ready
        output reg                          valid = 0, //       .valid
        output reg                          eop   = 0, //       .endofpacket
        
        output reg                          sop = 0,   //       .startofpacket


        output reg [63:0]                   timestamp,  // timestamp
        output reg [31:0]                   incl_length, // number of bytes in save pkt
        output reg [31:0]                   orig_length, // number of bytes in the original pkt

        output reg                          local_header_valid,

        output reg [15:0] pktcount = 0,
        output reg pcapfinished = 0
    );

    // buffers for message
    reg [7:0] global_header [0:23];
    reg [7:0] packet_header [0:15];
    reg newpkt = 0;
    
    integer swapped = 0;
    integer file = 0;
    integer r    = 0;
    integer eof  = 0;
    integer i    = 0;
    integer pktSz  = 0;
    integer diskSz = 0;
    integer nsPrecision = 0;
    integer timestamp_msb = 0;
    integer timestamp_lsb = 0;
    integer k;
    integer end_sim=0;


    reg [31:0] cnt_ifg;
    integer previous_packet_timestamp_msb;
    integer previous_packet_timestamp_lsb;

    wire [63:0] previous_packet_real_timestamp;
    wire [63:0] real_timestamp;

    reg [HEADER_SIZE_LENGTH+31:0] data_header; // for save hdr include timestamp
    
    reg [15:0] outgoing_pkts = 0,trans_num=0;

    reg internal_last;

    reg [2:0]                       hdr_size,consume_header;
    reg [$clog2(AXIS_WIDTH/8)-1:0]  wr_ptr;
    reg                             axis_handshake;
    reg [2:0]                       wr_ptr_aux_sum;
    reg [15:0]                      bytes_send;
    integer                         l;
    reg  [(AXIS_WIDTH/8)-1:0]       last_keep;







    localparam  READ_LOCAL_HEADER       =0,
                SEND_DATA               =1,
                SEND_DATA_N_DEF         =2,
                END_READ                =3;


    reg [2:0] state=READ_LOCAL_HEADER;


    // Debug Mode

    reg [8*10-1:0] state_char;
    always @(state,clk) begin
        case (state)                
            READ_LOCAL_HEADER: begin
                state_char <="HEADER";
            end    
            SEND_DATA: begin
                state_char <="DATA";                  
            end
            SEND_DATA_N_DEF: begin
                state_char <="NO_DFL_DATA";                  
            end        
            END_READ: begin
                state_char <="END_READ";                                     
            end
        endcase        
    end
 


    initial begin

        // open pcap file
        if (pcap_filename == "none") begin
            $display("pcap filename parameter not set");
            $finish; 
        end

        file = $fopen(pcap_filename, "rb");
        if (file == `NULL) begin
            $display("can't read pcap input %s", pcap_filename);
            $finish;
        end

        // Initialize Inputs
        $display("PCAP: %m reading from %s", pcap_filename);

        // read binary global_header
        r = $fread(global_header,file);
        
        // check magic signature to determine byte ordering
        if (global_header[3] == 8'hA1 && global_header[2] == 8'hB2) begin
            $display(" pcap endian: swapped");
            swapped = 1;
        end else if (global_header[0] == 8'hA1 && global_header[1] == 8'hB2) begin
            $display(" pcap endian: native");
            swapped = 0;
        end else begin
            $display(" pcap endian: unrecognised format");
            $finish; 
        end

        if ((swapped && global_header[0] == 8'h4D && global_header[1] == 8'h3C)
            || (global_header[3] == 8'h4D && global_header[2] == 8'h3C)) begin
            $display(" pcap precission: nanoseconds");
            nsPrecision = 1;
        end else if ((swapped && global_header[0] == 8'hD4 && global_header[1] == 8'hC3)
            || (global_header[3] == 8'hD4 && global_header[2] == 8'hC3)) begin
            $display(" pcap precission: microseconds");
            nsPrecision = 0;
        end else begin
            $display(" pcap magic number: unrecognised format");
            $finish; 
        end

        if (default_mode==1) begin
            hdr_size <= HEADER_SIZE_LENGTH/8;
        end
        else if (default_mode==2) begin // only support one timestamp
            hdr_size <= HEADER_SIZE_LENGTH/8 + 4;
        end

    end



    real        ns_per_cycle    = 1.0/CLOCK_FREQ_HZ*1e9;

    assign previous_packet_real_timestamp = nsPrecision ? 
                                previous_packet_timestamp_msb*1e9 + previous_packet_timestamp_lsb 
                                : previous_packet_timestamp_msb*1e6 + previous_packet_timestamp_lsb; 
    assign real_timestamp = nsPrecision ? 
                                timestamp_msb*1e9 + timestamp_lsb 
                                : timestamp_msb*1e6 + timestamp_lsb; 
    
    always @(posedge clk ) begin
        if(internal_last) begin
            previous_packet_timestamp_msb <= timestamp_msb;
            previous_packet_timestamp_lsb <= timestamp_lsb;
        end
    end    


    always @(posedge clk) begin
        if (reset) begin
            state           <= READ_LOCAL_HEADER;
            wr_ptr          <= 0;
            pcapfinished    <= 1'b0;
            data            <= {AXIS_WIDTH{1'b0}};
            keep            <= {AXIS_WIDTH/8{1'b0}};
            valid           <= 1'b0;
        end
        else begin

            case (state)
                READ_LOCAL_HEADER: begin

                    internal_last <= (internal_last & ~ready);
                    valid <= (valid & ~ready);
                    
                    if (axis_handshake) begin
                                           
                        r = $fread(packet_header, file);
                        eof = $feof(file);
                        if (swapped == 1) begin
                            timestamp_msb   = {packet_header[3],packet_header[2],packet_header[1],packet_header[0]};
                            timestamp_lsb   = {packet_header[7],packet_header[6],packet_header[5],packet_header[4]};
                            pktSz  = {packet_header[11],packet_header[10],packet_header[9] ,packet_header[8] };
                            diskSz = {packet_header[15],packet_header[14],packet_header[13],packet_header[12]};
                        end 
                        else begin
                            timestamp_msb   = {packet_header[0],packet_header[1],packet_header[2],packet_header[3]};
                            timestamp_lsb   = {packet_header[4],packet_header[5],packet_header[6],packet_header[7]};
                            pktSz =  {packet_header[ 8],packet_header[ 9],packet_header[10],packet_header[11]};
                            diskSz = {packet_header[12],packet_header[13],packet_header[14],packet_header[15]};
                        end

                        incl_length = pktSz[15:0];
                        orig_length = diskSz[15:0];
                        timestamp= {timestamp_msb,timestamp_lsb};

                        eof = $feof(file);
                        
                        if (eof !=0) begin
                            if (last_keep !=  {AXIS_WIDTH/8{1'b1}}) begin
                                valid <= 1'b1;
                                keep <= last_keep;
                            end

                            state <= END_READ;

                        end
                        else begin
                            if (default_mode==0) begin
                                state <= SEND_DATA;
                                //buf_wr_ptr = 0;
                            end
                            else begin
                                state <= SEND_DATA_N_DEF;
                            end
                            
                        end

                        data_header={timestamp[7:0],timestamp[15:8],timestamp[23:16],timestamp[31:24],diskSz[7:0],diskSz[15:8]};
                        consume_header = hdr_size;  // assign the amount on header size
                        bytes_send=0;
                    end




                end

                SEND_DATA: begin
                    
                    
                end

                SEND_DATA_N_DEF: begin

                    if (axis_handshake) begin
                        
                        keep <= {AXIS_WIDTH/8{1'b1}};
                        l=0;
                        if ((wr_ptr + consume_header) >= AXIS_WIDTH/8) begin // in this case a new valid transaction must be generate
                            
                            $display("Header can not be write in a complete transaction: consume_header: %d\twr_ptr: %d\ttime",consume_header,wr_ptr,$time);
                            

                            l=0;
                            for(k=wr_ptr ; k < AXIS_WIDTH/8 ; k=k+1) begin
                                data[k*8 +: 8] <= data_header[l*8 +:8];
                                l= l+ 1;
                                wr_ptr = wr_ptr + 1;
                                consume_header = consume_header - 1;
                            end

                            
                            // wr_ptr will be 0
                            $display("wr_ptr will be 0, and it is: %d\ttime",wr_ptr,$time);

                            valid <= 1'b1;
                            l=consume_header;
                        end
                        else begin
                            if (consume_header > 0) begin               // in this case in the transaction have enough space for at least one byte of data
                                
                                l= (consume_header!=hdr_size) ? consume_header : 0;
                                $display("Complete header can be write in current transaction, consume_header is: %d\twr_ptr: %d\tl: %d\ttime",consume_header,wr_ptr,l,$time);
                                
                                for(k=wr_ptr ; consume_header > 0 ; k=k+1 ) begin
                                    data[k*8 +: 8] <= data_header[l*8 +:8];
                                    l= l+ 1;
                                    wr_ptr = wr_ptr + 1;
                                    consume_header = consume_header - 1;
                                end



                            end
                            $display("Send data, wr_ptr: %d\tbytes_send: %d\tdiskSz: %d\ttime",wr_ptr,bytes_send,diskSz,$time);
                            
                            
                            for (k=wr_ptr ; k < AXIS_WIDTH/8 ; k = k+1) begin
                                if (bytes_send < incl_length[15:0]) begin
                                    data[(k*8) +:8] = $fgetc(file);
                                    last_keep[k] = 1'b1;
                                    wr_ptr = wr_ptr + 1;
                                    bytes_send= bytes_send+1;
                                    diskSz = diskSz - 1;
                                end
                                else begin
                                    data[k*8 +:8] = 8'h0;
                                    last_keep[k] = 1'b0;
                                end
                            end

                            if (wr_ptr==0) begin
                                valid <= 1'b1;
                            end
                            else begin
                                valid <= 1'b0;
                            end

                            if (diskSz==0) begin
                                internal_last <= 1'b1;
                                state <= READ_LOCAL_HEADER;
                            end
                        end 
                    end
                end

                END_READ: begin
                    if (axis_handshake) begin
                        pcapfinished    <= 1'b1;
                        data            <= {AXIS_WIDTH{1'b0}};
                        keep            <= {AXIS_WIDTH/8{1'b0}};
                        valid           <= 1'b0;
                    end
                end

            endcase

        end

    end

    assign axis_handshake = ((ready && valid) || (~ready && ~valid)) || ready;

    always @(*) begin
        if (default_mode==0) begin
            eop <= internal_last;
        end
    end




    always @(posedge clk) begin
        #1;
        if (valid && ready) begin

            $display("Packet: %d, part: %d\t data: %X",outgoing_pkts,trans_num,data, $time);
            trans_num <= trans_num + 1;

            if (internal_last) begin
                //$display("Entro al internal last");
                outgoing_pkts <= outgoing_pkts + 1;
                trans_num <= 0;
            end
            
        end
    
    end

endmodule