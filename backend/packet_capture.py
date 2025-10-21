"""
SpyNet Packet Capture Module

This module implements the PacketCapture class for network interface monitoring
using Scapy with threaded packet capture and queue-based buffering.
"""

import queue
import threading
import time
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

try:
    from scapy.all import sniff, get_if_list, Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
except ImportError as e:
    print(f"Error importing Scapy: {e}")
    print("Please install Scapy: pip install scapy")
    raise


@dataclass
class CapturedPacket:
    """Data class to hold captured packet information"""
    timestamp: datetime
    raw_packet: Packet
    interface: str
    size: int


class PacketCapture:
    """
    PacketCapture class for network interface monitoring using Scapy.
    
    Provides threaded packet capture with queue-based buffering and
    basic packet filtering capabilities.
    """
    
    def __init__(self, interface: str = None, buffer_size: int = 1000):
        """
        Initialize PacketCapture instance.
        
        Args:
            interface: Network interface to capture from (auto-detect if None)
            buffer_size: Maximum size of packet buffer queue
        """
        self.interface = interface or self._get_default_interface()
        self.buffer_size = buffer_size
        self.packet_queue = queue.Queue(maxsize=buffer_size)
        self.running = False
        self.capture_thread = None
        self.packet_count = 0
        self.dropped_packets = 0
        
        # Packet filtering options
        self.filter_string = ""
        self.capture_protocols = ["tcp", "udp", "icmp"]
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO) 
       
    def _get_default_interface(self) -> str:
        """
        Get the default network interface for packet capture.
        
        Returns:
            Default network interface name
        """
        try:
            interfaces = get_if_list()
            # Filter out loopback and virtual interfaces
            for iface in interfaces:
                if not iface.startswith(('lo', 'Loopback', 'vEthernet')):
                    return iface
            # Fallback to first available interface
            return interfaces[0] if interfaces else "eth0"
        except Exception as e:
            self.logger.warning(f"Could not detect interface: {e}")
            return "eth0"
    
    def get_available_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces.
        
        Returns:
            List of available network interface names
        """
        try:
            return get_if_list()
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return []
    
    def set_interface(self, interface: str) -> bool:
        """
        Set the network interface for packet capture.
        
        Args:
            interface: Network interface name
            
        Returns:
            True if interface is valid, False otherwise
        """
        available_interfaces = self.get_available_interfaces()
        if interface in available_interfaces:
            self.interface = interface
            self.logger.info(f"Interface set to: {interface}")
            return True
        else:
            self.logger.error(f"Interface {interface} not available")
            return False
    
    def set_filter(self, filter_string: str) -> None:
        """
        Set BPF (Berkeley Packet Filter) string for packet filtering.
        
        Args:
            filter_string: BPF filter string (e.g., "tcp port 80")
        """
        self.filter_string = filter_string
        self.logger.info(f"Packet filter set to: {filter_string}")
    
    def set_protocols(self, protocols: List[str]) -> None:
        """
        Set which protocols to capture.
        
        Args:
            protocols: List of protocols to capture (tcp, udp, icmp)
        """
        valid_protocols = ["tcp", "udp", "icmp"]
        self.capture_protocols = [p.lower() for p in protocols if p.lower() in valid_protocols]
        self.logger.info(f"Capture protocols set to: {self.capture_protocols}")
    
    def _packet_handler(self, packet: Packet) -> None:
        """
        Internal packet handler for Scapy sniff function.
        
        Args:
            packet: Captured packet from Scapy
        """
        try:
            # Create captured packet object
            captured_packet = CapturedPacket(
                timestamp=datetime.now(),
                raw_packet=packet,
                interface=self.interface,
                size=len(packet)
            )
            
            # Try to add packet to queue (non-blocking)
            try:
                self.packet_queue.put_nowait(captured_packet)
                self.packet_count += 1
            except queue.Full:
                self.dropped_packets += 1
                self.logger.warning("Packet buffer full, dropping packet")
                
        except Exception as e:
            self.logger.error(f"Error handling packet: {e}")
    
    def _capture_loop(self) -> None:
        """
        Main packet capture loop running in separate thread.
        """
        try:
            self.logger.info(f"Starting packet capture on interface: {self.interface}")
            
            # Build filter string based on protocols
            if self.capture_protocols:
                protocol_filter = " or ".join(self.capture_protocols)
                if self.filter_string:
                    combined_filter = f"({protocol_filter}) and ({self.filter_string})"
                else:
                    combined_filter = protocol_filter
            else:
                combined_filter = self.filter_string
            
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                filter=combined_filter if combined_filter else None,
                stop_filter=lambda x: not self.running,
                store=False  # Don't store packets in memory
            )
            
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
            self.running = False 
   
    def start_capture(self) -> bool:
        """
        Start packet capture in separate thread.
        
        Returns:
            True if capture started successfully, False otherwise
        """
        if self.running:
            self.logger.warning("Packet capture is already running")
            return False
        
        try:
            self.running = True
            self.packet_count = 0
            self.dropped_packets = 0
            
            # Start capture thread
            self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.capture_thread.start()
            
            self.logger.info("Packet capture started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start packet capture: {e}")
            self.running = False
            return False
    
    def stop_capture(self) -> None:
        """
        Stop packet capture gracefully.
        """
        if not self.running:
            self.logger.warning("Packet capture is not running")
            return
        
        self.logger.info("Stopping packet capture...")
        self.running = False
        
        # Wait for capture thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5.0)
        
        self.logger.info(f"Packet capture stopped. Captured: {self.packet_count}, Dropped: {self.dropped_packets}")
    
    def get_packet(self) -> Optional[CapturedPacket]:
        """
        Get next packet from queue (non-blocking).
        
        Returns:
            CapturedPacket object or None if queue is empty
        """
        try:
            return self.packet_queue.get_nowait()
        except queue.Empty:
            return None
    
    def get_packet_blocking(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        """
        Get next packet from queue (blocking with timeout).
        
        Args:
            timeout: Maximum time to wait for packet
            
        Returns:
            CapturedPacket object or None if timeout
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def get_queue_size(self) -> int:
        """
        Get current number of packets in queue.
        
        Returns:
            Number of packets in queue
        """
        return self.packet_queue.qsize()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get packet capture statistics.
        
        Returns:
            Dictionary containing capture statistics
        """
        return {
            "interface": self.interface,
            "running": self.running,
            "packets_captured": self.packet_count,
            "packets_dropped": self.dropped_packets,
            "queue_size": self.get_queue_size(),
            "buffer_size": self.buffer_size,
            "filter": self.filter_string,
            "protocols": self.capture_protocols
        }
    
    def clear_queue(self) -> int:
        """
        Clear all packets from the queue.
        
        Returns:
            Number of packets cleared
        """
        cleared_count = 0
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
                cleared_count += 1
            except queue.Empty:
                break
        
        self.logger.info(f"Cleared {cleared_count} packets from queue")
        return cleared_count
    
    def is_running(self) -> bool:
        """
        Check if packet capture is currently running.
        
        Returns:
            True if capture is running, False otherwise
        """
        return self.running
    
    def __enter__(self):
        """Context manager entry"""
        self.start_capture()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop_capture()

if __name__ == "__main__":
    # Simple test of packet capture functionality
    print("SpyNet Packet Capture Test")
    print("=" * 30)
    
    # Create packet capture instance
    capture = PacketCapture()
    
    print(f"Available interfaces: {capture.get_available_interfaces()}")
    print(f"Using interface: {capture.interface}")
    
    # Start capture
    if capture.start_capture():
        print("Packet capture started. Capturing for 10 seconds...")
        
        try:
            # Capture packets for 10 seconds
            start_time = time.time()
            while time.time() - start_time < 10:
                packet = capture.get_packet()
                if packet:
                    print(f"Captured packet: {packet.size} bytes at {packet.timestamp}")
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\nCapture interrupted by user")
        
        # Stop capture and show statistics
        capture.stop_capture()
        stats = capture.get_statistics()
        print(f"\nCapture Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    
    else:
        print("Failed to start packet capture")