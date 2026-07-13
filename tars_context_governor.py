import re
from typing import List, Tuple, Dict, Optional

class ContextGovernor:
    """
    Enforces the cognitive attention bottleneck.
    Decides what enters the final system prompt.
    Normal target: 4k-6k chars. Hard cap: 8k chars.
    """
    NORMAL_BUDGET = 6000
    HARD_CAP = 8000

    def extract_soul_core(self, soul_text: str) -> str:
        """Extracts only the Identity, Personality, and Reality Discipline sections."""
        lines = soul_text.splitlines()
        core_lines = []
        keep = False
        for line in lines:
            if line.startswith("## Identity") or line.startswith("## Personality") or line.startswith("## Reality / Capability Discipline") or line.startswith("## Voice Rules"):
                keep = True
                core_lines.append(line)
            elif line.startswith("## "):
                keep = False
            elif keep:
                core_lines.append(line)
                
        # Fallback if sections aren't found cleanly
        if len(core_lines) < 5:
             return soul_text[:1200] + "\n... [SOUL TRUNCATED]"
             
        return "\n".join(core_lines).strip()

    def should_include_world_model(self, workspace_frame: Optional[Dict], appraisal: Optional[Dict], user_text: Optional[str]) -> bool:
        if not workspace_frame: return False
        winner = workspace_frame.get("winner")
        if not winner: return False
        
        # Include if workspace explicitly focuses on the world
        source = winner.get("source", "")
        if source == "world": return True
        
        # Include if uncertainty is high
        if appraisal and appraisal.get("uncertainty", 0.0) > 0.6: return True
        
        # Include if user explicitly asks about situation/prediction
        if user_text and any(w in user_text.lower() for w in ["what do you think", "what is happening", "predict", "situation"]): return True
        
        return False

    def should_include_self_model(self, workspace_frame: Optional[Dict], appraisal: Optional[Dict], user_text: Optional[str]) -> bool:
        if not workspace_frame: return False
        winner = workspace_frame.get("winner")
        if not winner: return False
        
        # Include if workspace explicitly focuses on self
        source = winner.get("source", "")
        if source in ["self", "skill_result", "skill_failure", "sleep_summary"]: return True
        
        # Include if uncertainty is extremely high (identity confusion)
        if appraisal and appraisal.get("uncertainty", 0.0) > 0.8: return True
        
        # Include if user asks about capabilities
        if user_text and any(w in user_text.lower() for w in ["can you", "are you able", "your status", "how are you performing"]): return True
        
        return False

    def compact_memory(self, memory_payload: str, max_items: int = 3) -> str:
        """Takes the formatted memory string and trims it if it has too many bullet points."""
        if not memory_payload: return ""
        
        # Rough heuristic: split by double newline or bullet points
        blocks = re.split(r'\n\n(?=[\-\*] )', memory_payload)
        if len(blocks) > max_items + 1: # +1 for header
            # Keep header and top N items
            return "\n\n".join(blocks[:max_items+1]) + "\n  [Memory truncated by governor]"
        return memory_payload

    def enforce_budget(self, sections: List[Tuple[str, str]]) -> str:
        """
        Takes a list of (section_name, content) tuples.
        Greedily adds sections according to budget priorities.
        Budget priorities (implied by input list order):
        0. Identity Core
        1. Workspace Winner
        2. Appraisal
        3. Selected Memory
        4. World Model (Optional)
        5. Self-Model (Optional)
        6. Recent Inner Thoughts
        7. Concerns/Goals
        """
        final_prompt = ""
        
        for name, content in sections:
            if not content.strip(): continue
            
            proposed = final_prompt + ("\n\n" if final_prompt else "") + content
            if len(proposed) <= self.HARD_CAP:
                final_prompt = proposed
            else:
                # If it's the core or workspace, we force it in even if we break budget slightly, 
                # but we truncate it to fit hard cap if absolutely necessary.
                if name in ["Identity Core", "Current Workspace"]:
                    allowance = max(0, self.HARD_CAP - len(final_prompt))
                    if allowance > 100:
                        final_prompt += ("\n\n" if final_prompt else "") + content[:allowance] + "... [TRUNCATED]"
                # Otherwise, drop the section
                pass 
                
        return final_prompt

    def build_context(
        self,
        soul_text: str,
        workspace_content: str,
        appraisal_content: str,
        memory_content: str,
        inner_thoughts_content: str,
        world_state_content: str,
        self_model_content: str,
        concerns_goals_content: str,
        workspace_frame: Optional[Dict] = None,
        appraisal_dict: Optional[Dict] = None,
        user_text: Optional[str] = None,
    ) -> str:
        
        # 1. Extract Core Soul
        core_soul = self.extract_soul_core(soul_text)
        
        # 2. Compact Memory
        compacted_memory = self.compact_memory(memory_content)
        
        # 3. Determine Optional Sections
        include_world = self.should_include_world_model(workspace_frame, appraisal_dict, user_text)
        include_self = self.should_include_self_model(workspace_frame, appraisal_dict, user_text)
        
        # 4. Build prioritized list
        sections = [
            ("Identity Core", core_soul),
            ("Current Workspace", workspace_content),
            ("Current Appraisal", appraisal_content),
            ("Selected Memory", compacted_memory)
        ]
        
        if include_world and world_state_content:
            sections.append(("World Model", world_state_content))
            
        if include_self and self_model_content:
            sections.append(("Self Model", self_model_content))
            
        # These are lowest priority
        sections.append(("Recent Inner Thoughts", inner_thoughts_content))
        sections.append(("Concerns/Goals", concerns_goals_content))
        
        # 5. Enforce Budget
        return self.enforce_budget(sections)

