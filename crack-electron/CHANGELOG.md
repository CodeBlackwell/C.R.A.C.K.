# Changelog

All notable changes to the CRACK Electron application will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New ChainStepDetails component for displaying individual attack chain step information
- Step-level navigation in chain graph view with clickable nodes
- Three-button navigation panel (Chain Graph / Chain Step / List View) in right panel
- Visual distinction between steps with and without commands (blue vs gray nodes)
- Command names now display on chain graph nodes alongside step numbers
- "Clear step" functionality to return to chain overview from step details
- Enhanced debug logging for chain graph interactions

### Fixed
- Chain graph now persists when clicking step nodes (no longer disappears)
- Callback functions properly memoized with useCallback to prevent unnecessary re-renders
- Cytoscape instance no longer destroyed when navigating between steps
- Graph visualization maintains state during step navigation

### Changed
- Chain graph nodes increased in size (80px → 120px) for better readability
- Node labels now show both command name and step number
- Updated legend to reflect "With Command" vs "No Command" instead of generic "Attack Step"
- Improved click handler to show step details in right panel while keeping graph visible
- ChainControlsPanel now conditionally displays step details or chain metadata

### Technical
- Added useCallback hooks to App.tsx for stable callback references
- Updated ChainGraphView dependency arrays to include onStepClick
- Added onClearStep callback prop to ChainControlsPanel
- Removed unnecessary state dependencies from handleStepClick to prevent re-renders

## [0.1.0] - 2025-01-XX

### Initial Features
- Attack chain visualization with Cytoscape.js
- Neo4j database integration
- Command search and relationship graph
- Cheatsheet browsing and display
- Three-column layout (search/graph/details)
