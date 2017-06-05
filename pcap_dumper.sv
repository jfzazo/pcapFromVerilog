//==================================================================================================
// -----------------------------------------------------------------------------
// Copyright (c) 2017 All rights reserved
// -----------------------------------------------------------------------------
//  Filename      : pcap_dumper.sv
//  Author        : Jose Fernando Zazo Rollon
//  Company       : Naudit
//  Email         : josefernando.zazo@naudit.es
//  Created On    : 2017-06-02 16:11:52
//  Last Modified : 2017-06-05 14:01:41
//
//  Revision      : 1.0
//
//  Description   : Utility to dump packets from an AXI4 Stream interface to a pcap file for its use 
//  in network test benches.
//==================================================================================================
`timescale 1ns / 1ps
`define NULL 0
`define abs(a) ((a)<0 ? -(a):(a))



module pcap_dumper #(
    parameter pcap_filename   = "none",
    parameter c_max_pkt_size = 2048     ,
    parameter c_caplen       = 0        ,
    parameter c_ns_precision = 1        ,
    parameter CLOCK_FREQ_HZ  = 156250000,
    parameter AXIS_WIDTH     = 64
) (
    input  wire                      clk     ,
    input  wire                      rst_n   ,
    input  wire [    AXIS_WIDTH-1:0] tdata   ,
    input  wire [(AXIS_WIDTH/8)-1:0] tstrb   ,
    output wire                      tready  ,
    input  wire                      tvalid  ,
    input  wire                      tlast   ,
    output reg  [               7:0] pktcount
);

    assign tready = 1'b1;


    // buffers for message
    reg [7:0] global_header[            0:23]    ;
    reg [7:0] packet_header[            0:15]    ;
    reg [7:0] pkt_buffer   [0:c_max_pkt_size]    ;

    integer file          = 0;
    integer r             = 0;
    integer i             = 0;
    integer j                ;
    integer pktSz         = 0;
    integer diskSz        = 0;
    integer timestamp_msb = 0;
    integer timestamp_lsb = 0;

    initial begin

        // open pcap file
        if (pcap_filename == "none") begin
            $display("pcap filename parameter not set");
            $finish;
        end

        file = $fopen(pcap_filename, "wb");
        if (file == `NULL) begin
            $display("can't open output pcap %s", pcap_filename);
            $finish;
        end

        // Initialize Inputs
        $display("PCAP: %m writing to %s", pcap_filename);

        // Magic code
        global_header[3] = 8'hA1;
        global_header[2] = 8'hB2;
        if(!c_ns_precision) begin // Precision of microseconds.
            global_header[1] = 8'hC3;
            global_header[0] = 8'hD4;
        end else begin // Precision of nanoseconds.
            global_header[1] = 8'h3C;
            global_header[0] = 8'h4D;
        end

        // Version. Major-minor 2.4
        global_header[7] = 8'h0;
        global_header[6] = 8'h4; // Minor

        global_header[5] = 8'h0;
        global_header[4] = 8'h2; // Major

        // Snaplen
        global_header[16] = 8'hff;
        global_header[17] = 8'hff;
        global_header[18] = 8'hff;
        global_header[19] = 8'hff;

        // Data link type
        global_header[20] = 8'h01;

        // Write binary global_header
        foreach(global_header[i])
            $fwrite(file,"%c",global_header[i]);

    end

    reg  [63:0] real_timestamp                        ;
    real        ns_per_cycle   = 1.0/CLOCK_FREQ_HZ*1e9;


    always_ff @(negedge rst_n or posedge clk) begin
        if(~rst_n) begin
            pktSz          = 0;
            diskSz         = 0;
            real_timestamp = 0;
            pktcount       = 0;
        end else begin
            real_timestamp+=ns_per_cycle;

            if(tvalid && tready) begin
                for(i=0;i<AXIS_WIDTH/8;i++) begin
                    if(tstrb[i]) begin
                        pkt_buffer[pktSz] = tdata[8*i+:8];
                        pktSz++;
                    end
                end

                if(tlast) begin
                    pktcount++;
                    diskSz        = c_caplen == 0 ? pktSz : pktSz<c_caplen ? pktSz : c_caplen;
                    $display("PCAP:  packet %0d: incl_length %0d orig_length %0d", pktcount, diskSz, pktSz  );
                    timestamp_msb = c_ns_precision ?
                        real_timestamp/1e9
                        : timestamp_msb/1e6;
                    timestamp_lsb = c_ns_precision ?
                        real_timestamp%1000000000
                        : timestamp_msb%1000000;

                    {packet_header[3], packet_header[2], packet_header[1], packet_header[0]} = timestamp_msb;
                    {packet_header[7], packet_header[6], packet_header[5], packet_header[4]} = timestamp_lsb;
                    {packet_header[11],packet_header[10],packet_header[9] ,packet_header[8] } = diskSz  ;
                    {packet_header[15],packet_header[14],packet_header[13],packet_header[12]} = pktSz ;

                    foreach(packet_header[i])
                        $fwrite(file,"%c",packet_header[i]);

                    for(j=0;j<diskSz;j++) begin
                        $fwrite(file,"%c",pkt_buffer[j]);
                    end
                    pktSz          = 0;
                end
            end
        end
    end
endmodule
