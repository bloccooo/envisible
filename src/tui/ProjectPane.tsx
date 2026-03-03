import React from "react";
import { Box, Text } from "ink";
import type { Project } from "../types";

export const ProjectPane = ({
  projects,
  selected,
  focused,
}: {
  projects: Project[];
  selected: number;
  focused: boolean;
}) => {
  const color = focused ? "cyan" : "gray";
  return (
    <Box flexDirection="column" width={26} borderStyle="round" borderColor={color}>
      <Text bold color={color}> Projects</Text>
      {projects.length === 0 ? (
        <Text dimColor>  (none)</Text>
      ) : (
        projects.map((p, i) => (
          <Text key={p.id} color={i === selected && focused ? "cyan" : "white"}>
            {i === selected ? "› " : "  "}
            {p.name}
            <Text dimColor> ({p.secret_ids.length})</Text>
          </Text>
        ))
      )}
    </Box>
  );
};
