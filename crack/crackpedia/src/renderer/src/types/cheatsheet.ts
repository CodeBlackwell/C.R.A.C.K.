export interface Cheatsheet {
  id: string;
  name: string;
  description: string;
  tags?: string[];
  educational_header?: EducationalHeader;
  scenarios?: CheatsheetScenario[];
  sections?: CheatsheetSection[];
}

export interface EducationalHeader {
  how_to_recognize?: string[];
  when_to_look_for?: string[];
}

export interface CheatsheetScenario {
  title: string;
  context?: string;
  approach?: string;
  commands?: (string | SectionCommand)[];  // Support both string IDs and enriched objects
  expected_outcome?: string;
  why_this_works?: string;
}

// Command reference in section - can be string ID or enriched object
export interface SectionCommand {
  id: string;
  example: string;
  shows: string;
}

export interface CheatsheetSection {
  title: string;
  notes?: string;
  commands?: (string | SectionCommand)[];  // Support both string IDs and enriched objects
}

// List view item (minimal data for search results)
export interface CheatsheetListItem {
  id: string;
  name: string;
  description: string;
  tags: string[];
  category?: string;
}
