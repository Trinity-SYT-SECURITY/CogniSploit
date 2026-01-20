"""
AI Conversation Controller
Manages browser-based chat sessions with AI targets for security testing
"""
import asyncio
import time
import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ConversationMessage:
    """Represents a single message in the conversation"""
    role: str  # 'attacker' or 'target'
    content: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict = field(default_factory=dict)


class AIConversationController:
    """
    Controls browser-based conversations with target AI chatbots.
    
    Manages session lifecycle, message sending/receiving, and conversation
    history for adaptive security testing scenarios.
    """
    
    def __init__(self, page, logger_instance=None, max_interactions: int = 20):
        """
        Initialize the conversation controller.
        
        Parameters:
            page: Playwright page object for browser interaction
            logger_instance: Logger for output
            max_interactions: Maximum allowed interactions per session
        """
        self.page = page
        self.logger = logger_instance or logger
        self.max_interactions = max_interactions
        self.interaction_count = 0
        self.conversation_history: List[ConversationMessage] = []
        self.chat_interface: Optional[Dict] = None
        self.session_start_time: Optional[float] = None
        self.last_response_time: Optional[float] = None
        
        # Interface detection patterns (dynamically built, not hardcoded)
        self._input_selectors = self._build_input_selectors()
        self._button_selectors = self._build_button_selectors()
        self._response_selectors = self._build_response_selectors()
    
    def _build_input_selectors(self) -> List[str]:
        """Build dynamic selectors for chat input detection"""
        # Semantic patterns for chat inputs
        input_patterns = [
            'textarea[placeholder*="message" i]',
            'textarea[placeholder*="type" i]',
            'textarea[aria-label*="message" i]',
            'input[type="text"][placeholder*="message" i]',
            '[contenteditable="true"][role="textbox"]',
            '[data-testid*="input" i]',
            '[class*="chat" i] textarea',
            '[class*="message" i] textarea',
            '[id*="chat" i] textarea',
            '[id*="message" i] input',
            'div[role="textbox"]',
            '[class*="composer" i] textarea',
        ]
        return input_patterns
    
    def _build_button_selectors(self) -> List[str]:
        """Build dynamic selectors for send button detection"""
        button_patterns = [
            'button[type="submit"]',
            'button[aria-label*="send" i]',
            'button[class*="send" i]',
            '[data-testid*="send" i]',
            'button:has(svg[class*="send" i])',
            '[class*="submit" i] button',
            'button[title*="send" i]',
            '[role="button"][aria-label*="send" i]',
        ]
        return button_patterns
    
    def _build_response_selectors(self) -> List[str]:
        """Build dynamic selectors for response detection"""
        response_patterns = [
            '[class*="assistant" i]',
            '[class*="bot" i][class*="message" i]',
            '[class*="ai" i][class*="response" i]',
            '[data-role="assistant"]',
            '[class*="response" i]:not([class*="user" i])',
            '[class*="message" i][class*="received" i]',
            '[data-testid*="response" i]',
            '[class*="chat" i] [class*="reply" i]',
        ]
        return response_patterns
    
    async def detect_chat_interface(self) -> Optional[Dict]:
        """
        Detect chat interface elements on the current page.
        
        Returns:
            Dictionary with detected interface elements or None
        """
        try:
            interface = {
                'input_element': None,
                'send_button': None,
                'response_container': None,
                'detection_confidence': 0.0,
                'interface_type': 'unknown'
            }
            
            # Detect input element
            for selector in self._input_selectors:
                try:
                    element = await self.page.wait_for_selector(selector, timeout=2000)
                    if element and await element.is_visible():
                        interface['input_element'] = selector
                        interface['detection_confidence'] += 0.4
                        break
                except Exception:
                    continue
            
            # Detect send button
            for selector in self._button_selectors:
                try:
                    element = await self.page.wait_for_selector(selector, timeout=1000)
                    if element and await element.is_visible():
                        interface['send_button'] = selector
                        interface['detection_confidence'] += 0.3
                        break
                except Exception:
                    continue
            
            # Detect response container
            for selector in self._response_selectors:
                try:
                    elements = await self.page.query_selector_all(selector)
                    if elements:
                        interface['response_container'] = selector
                        interface['detection_confidence'] += 0.3
                        break
                except Exception:
                    continue
            
            # Determine interface type
            if interface['detection_confidence'] >= 0.7:
                interface['interface_type'] = 'standard_chat'
            elif interface['detection_confidence'] >= 0.4:
                interface['interface_type'] = 'partial_detection'
            
            if interface['input_element']:
                self.chat_interface = interface
                self.session_start_time = time.time()
                self.logger.info(f"[ConversationController] Detected chat interface with confidence: {interface['detection_confidence']:.2f}")
                return interface
            
            return None
            
        except Exception as e:
            self.logger.error(f"[ConversationController] Interface detection error: {str(e)}")
            return None
    
    async def send_message(self, message: str, wait_for_response: bool = True) -> Optional[str]:
        """
        Send a message to the target AI and optionally wait for response.
        
        Parameters:
            message: The message content to send
            wait_for_response: Whether to wait for and capture the response
            
        Returns:
            The AI's response text or None if failed
        """
        if not self.chat_interface or not self.chat_interface.get('input_element'):
            self.logger.error("[ConversationController] No chat interface detected")
            return None
        
        if self.interaction_count >= self.max_interactions:
            self.logger.warning("[ConversationController] Interaction limit reached")
            return None
        
        try:
            # Get current response count for comparison
            initial_response_count = await self._get_response_count()
            
            # Type the message
            input_selector = self.chat_interface['input_element']
            await self.page.click(input_selector)
            await self.page.fill(input_selector, message)
            
            # Small delay for natural typing simulation
            await asyncio.sleep(0.2)
            
            # Send the message
            if self.chat_interface.get('send_button'):
                await self.page.click(self.chat_interface['send_button'])
            else:
                # Try Enter key if no button found
                await self.page.keyboard.press('Enter')
            
            # Record the sent message
            self.conversation_history.append(ConversationMessage(
                role='attacker',
                content=message,
                metadata={'interaction_number': self.interaction_count}
            ))
            self.interaction_count += 1
            
            if not wait_for_response:
                return None
            
            # Wait for response
            response = await self._wait_for_response(initial_response_count)
            
            if response:
                self.conversation_history.append(ConversationMessage(
                    role='target',
                    content=response,
                    metadata={'interaction_number': self.interaction_count - 1}
                ))
                self.last_response_time = time.time()
            
            return response
            
        except Exception as e:
            self.logger.error(f"[ConversationController] Send message error: {str(e)}")
            return None
    
    async def _get_response_count(self) -> int:
        """Get current count of response messages"""
        if not self.chat_interface or not self.chat_interface.get('response_container'):
            return 0
        
        try:
            elements = await self.page.query_selector_all(
                self.chat_interface['response_container']
            )
            return len(elements)
        except Exception:
            return 0
    
    async def _wait_for_response(self, initial_count: int, timeout: float = 30.0) -> Optional[str]:
        """
        Wait for a new response from the target AI.
        
        Parameters:
            initial_count: Initial response count before sending message
            timeout: Maximum wait time in seconds
            
        Returns:
            The response text or None
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                current_count = await self._get_response_count()
                
                if current_count > initial_count:
                    # New response detected
                    await asyncio.sleep(1.0)  # Wait for response to complete
                    
                    # Get the latest response
                    if self.chat_interface.get('response_container'):
                        elements = await self.page.query_selector_all(
                            self.chat_interface['response_container']
                        )
                        if elements:
                            latest = elements[-1]
                            response_text = await latest.inner_text()
                            return response_text.strip()
                
                await asyncio.sleep(0.5)
                
            except Exception as e:
                self.logger.debug(f"[ConversationController] Response wait error: {str(e)}")
                await asyncio.sleep(0.5)
        
        self.logger.warning("[ConversationController] Response timeout")
        return None
    
    def get_conversation_history(self) -> List[Dict]:
        """
        Get the full conversation history.
        
        Returns:
            List of conversation messages as dictionaries
        """
        return [
            {
                'role': msg.role,
                'content': msg.content,
                'timestamp': msg.timestamp,
                'metadata': msg.metadata
            }
            for msg in self.conversation_history
        ]
    
    def get_last_exchange(self) -> Optional[Tuple[str, str]]:
        """
        Get the last message-response pair.
        
        Returns:
            Tuple of (sent_message, response) or None
        """
        if len(self.conversation_history) < 2:
            return None
        
        # Find last attacker message and subsequent target response
        for i in range(len(self.conversation_history) - 1, 0, -1):
            if self.conversation_history[i].role == 'target':
                if self.conversation_history[i-1].role == 'attacker':
                    return (
                        self.conversation_history[i-1].content,
                        self.conversation_history[i].content
                    )
        
        return None
    
    async def reset_session(self) -> bool:
        """
        Reset the conversation session.
        
        Returns:
            True if successful
        """
        try:
            # Try to find and click reset/new chat button
            reset_selectors = [
                'button[aria-label*="new" i]',
                'button[class*="reset" i]',
                'button[class*="clear" i]',
                '[data-testid*="new" i]',
            ]
            
            for selector in reset_selectors:
                try:
                    element = await self.page.query_selector(selector)
                    if element and await element.is_visible():
                        await element.click()
                        await asyncio.sleep(1.0)
                        break
                except Exception:
                    continue
            
            # Reload page as fallback
            await self.page.reload()
            await asyncio.sleep(2.0)
            
            # Reset internal state
            self.conversation_history.clear()
            self.interaction_count = 0
            self.session_start_time = time.time()
            
            # Re-detect interface
            await self.detect_chat_interface()
            
            return True
            
        except Exception as e:
            self.logger.error(f"[ConversationController] Session reset error: {str(e)}")
            return False
    
    def is_session_alive(self) -> bool:
        """
        Check if the current session is still active and usable.
        
        Returns:
            True if session can continue
        """
        if not self.chat_interface:
            return False
        
        if self.interaction_count >= self.max_interactions:
            return False
        
        return True
    
    def get_session_stats(self) -> Dict:
        """
        Get statistics about the current session.
        
        Returns:
            Dictionary with session statistics
        """
        return {
            'interaction_count': self.interaction_count,
            'max_interactions': self.max_interactions,
            'remaining_interactions': self.max_interactions - self.interaction_count,
            'session_duration': time.time() - self.session_start_time if self.session_start_time else 0,
            'message_count': len(self.conversation_history),
            'last_response_time': self.last_response_time,
            'interface_detected': self.chat_interface is not None,
            'interface_confidence': self.chat_interface.get('detection_confidence', 0) if self.chat_interface else 0
        }
