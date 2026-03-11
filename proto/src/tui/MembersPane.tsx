import React from "react";
import { Box, Text } from "ink";
import type { Member } from "../types";

export const MembersPane = ({
  members,
  selected,
  focused,
  currentMemberId,
}: {
  members: Member[];
  selected: number;
  focused: boolean;
  currentMemberId: string;
}) => {
  const color = focused ? "cyan" : "gray";
  return (
    <Box flexDirection="column" borderStyle="round" borderColor={color} width="100%">
      <Text bold color={color}> Members</Text>
      {members.length === 0 ? (
        <Text dimColor>  (none)</Text>
      ) : (
        members.map((m, i) => {
          const isYou = m.id === currentMemberId;
          const isPending = !m.wrappedDek;
          const isSelected = i === selected && focused;
          return (
            <Box key={m.id}>
              <Text color={isSelected ? "cyan" : "white"}>
                {i === selected ? "› " : "  "}
                <Text color={isPending ? "yellow" : "green"}>
                  {isPending ? "pending" : "active "}
                </Text>
                {"  "}
                <Text>{m.email}</Text>
                {isYou && <Text color="cyan"> (you)</Text>}
              </Text>
            </Box>
          );
        })
      )}
    </Box>
  );
};
