`timescale 1ns / 1ps
`define NULL 0
`define abs(a) ((a)<0 ? -(a):(a))


// Engineer:    Jose Fernando Zazo
// Description:
//    Utility to replay a packets from a pcap file over a 64-bit for use in network test benches.
//  Based on the original work of Chris Shucksmith (https://github.com/shuckc/)


module pcap_parse
    #(
        parameter pcap_filename   = "none",
        parameter use_custom_ifg  = "TRUE",   
        parameter default_ifg     = 6,
		parameter CLOCK_FREQ_HZ   = 156250000,
		parameter AXIS_WIDTH      = 64
	) (
		input pause,

		output reg  [AXIS_WIDTH-1:0]      data,      //       .data
		output reg  [(AXIS_WIDTH/8)-1:0]  strb,      //       .strb
        input  wire                       ready,     //       .ready
        output reg                        valid = 0, //       .valid
        output reg                        sop = 0,   //       .startofpacket
        output reg                        eop = 0,   //       .endofpacket
        input  wire                       clk,       //       clk

        output reg [7:0] pktcount = 0,
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

    end


    reg pause_ifg = 0;
    reg [1:0]  state_ifg = 0; 
    reg [31:0] cnt_ifg;
    integer previous_packet_timestamp_msb;
    integer previous_packet_timestamp_lsb;

    wire [63:0] previous_packet_real_timestamp;
    wire [63:0] real_timestamp;
    real        ns_per_cycle    = 1.0/CLOCK_FREQ_HZ*1e9;

    assign previous_packet_real_timestamp = nsPrecision ? 
                                previous_packet_timestamp_msb*1e9 + previous_packet_timestamp_lsb 
                                : previous_packet_timestamp_msb*1e6 + previous_packet_timestamp_lsb; 
    assign real_timestamp = nsPrecision ? 
                                timestamp_msb*1e9 + timestamp_lsb 
                                : timestamp_msb*1e6 + timestamp_lsb; 
    always @(posedge clk ) begin
         if(eop) begin
            previous_packet_timestamp_msb <= timestamp_msb;
            previous_packet_timestamp_lsb <= timestamp_lsb;
        end
    end    

    always @(posedge clk ) begin
        case(state_ifg)
            2'b0:   begin
                if(eop) begin
                    if(use_custom_ifg == "TRUE") begin
                        pause_ifg <= 1'b1;
                        state_ifg <= 2'b10;
                        cnt_ifg   <= default_ifg;
                    end else begin       // The header of the next packect has to be read. Wait one pulse.
                        pause_ifg <= 1'b1;
                        state_ifg <= 2'b01;
                    end
                end
            end
            2'b01: begin // Substract the timestamps from two consecutives packets and assign the new 
                         // ifg. Notice one has been consumed.
                if(nsPrecision) begin
                    if(`abs(real_timestamp - previous_packet_real_timestamp)/ns_per_cycle > 1) begin
                        cnt_ifg   <= $ceil(`abs(real_timestamp - previous_packet_real_timestamp)/ns_per_cycle) - 1;
                        state_ifg <= 2'b10;    
                    end else begin
                        state_ifg <= 2'b00;
                        pause_ifg <= 1'b0;
                    end
                end else begin // Time in us.
                    if(`abs(real_timestamp - previous_packet_real_timestamp)/ns_per_cycle > 1) begin
                        cnt_ifg   <= $ceil((`abs(real_timestamp - previous_packet_real_timestamp)*1e3)/ns_per_cycle) - 1;
                        state_ifg <= 2'b10;    
                    end else begin
                        state_ifg <= 2'b00;
                        pause_ifg <= 1'b0;
                    end
                end
            end
            2'b10: begin
                if(cnt_ifg == 1) begin
                    state_ifg <= 2'b00;
                    pause_ifg <= 1'b0;
                end else begin
                    cnt_ifg <= cnt_ifg - 1;
                end
                
            end
            default: begin
                pause_ifg <= 1'b0; 
                state_ifg <= 1'b0;
            end
        endcase
    end

    always @(posedge clk) begin
        eof = $feof(file);
        
        if (eof != 0) begin
            pcapfinished <= 1;    // terminal loop here
            eop <= 0;
            sop <= 0;
            valid <= 0;
            data <= {AXIS_WIDTH{1'b0}};
        end else if (ready && diskSz == 0) begin
            // read packet header
            // fields of interest are U32 so bear in mind the byte ordering when assembling
            // multibyte fields
            r = $fread(packet_header, file);
            if (swapped == 1) begin
                timestamp_msb   = {packet_header[3],packet_header[2],packet_header[1],packet_header[0] };
                timestamp_lsb   = {packet_header[7],packet_header[6],packet_header[5],packet_header[4] };
                pktSz  = {packet_header[11],packet_header[10],packet_header[9] ,packet_header[8] };
                diskSz = {packet_header[15],packet_header[14],packet_header[13],packet_header[12]};
            end else begin
                timestamp_msb   = {packet_header[0],packet_header[1],packet_header[2],packet_header[3] };
                timestamp_lsb   = {packet_header[4],packet_header[5],packet_header[6],packet_header[7] };
                pktSz =  {packet_header[ 8],packet_header[ 9],packet_header[10],packet_header[11]};
                diskSz = {packet_header[12],packet_header[13],packet_header[14],packet_header[15]};
            end

            $display("PCAP:  packet %0d: incl_length %0d orig_length %0d", pktcount, pktSz, diskSz );

            newpkt <= 1;
            pktcount <= pktcount + 1;

            eop <= 0;
            sop <= 0;
            valid <= 0;
        end else if ( diskSz > 0) begin

            // packet content is byte-aligned, no swapping required
            if (~pause && ~pause_ifg && ready) begin

                newpkt <= 0;
                diskSz <= (diskSz > AXIS_WIDTH/8-1) ? diskSz - AXIS_WIDTH/8 : 0;

                sop <= newpkt;
                eop <= diskSz <= AXIS_WIDTH/8;

                for (k=0 ; k < AXIS_WIDTH/8 ; k = k+1) begin
                    if (diskSz < k+1) begin
                        data[k*8+:8] <= 8'b0;
                        strb[k]=1'b0;
                    end else begin
                        data[k*8+:8] <= $fgetc(file);
                        strb[k]=1'b1;
                    end
                end 

                valid <= 1;
            end else begin
                if(valid && ~ready) begin
                   valid <= 1;          
                end else begin
                   valid <= 0; 
                end
            end
        end 


    end

endmodule
