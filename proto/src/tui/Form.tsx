import React from "react";
import { Box, Text } from "ink";

export type FormField = {
  label: string;
  secret?: boolean;
};

export const Form = ({
  title,
  fields,
  currentField,
  completedValues,
  currentInput,
  cursor,
}: {
  title: string;
  fields: FormField[];
  currentField: number;
  completedValues: string[];
  currentInput: string;
  cursor: number;
}) => (
  <Box flexDirection="column" borderStyle="round" borderColor="cyan" padding={1}>
    <Text bold color="cyan">
      {title}
    </Text>
    <Box marginTop={1} flexDirection="column" gap={0}>
      {fields.map((f, i) => {
        const isDone = i < currentField;
        const isCurrent = i === currentField;
        const value = isDone ? completedValues[i] : isCurrent ? currentInput : "";
        const display = f.secret && isDone ? "••••••••" : (value ?? "");

        return (
          <Box key={f.label}>
            <Text color={isCurrent ? "cyan" : isDone ? "green" : "gray"}>
              {isCurrent ? "› " : isDone ? "✓ " : "  "}
              {f.label}:{" "}
            </Text>
            {isCurrent ? (
              <>
                <Text color="white">{display.slice(0, cursor)}</Text>
                <Text backgroundColor="white" color="black">
                  {display[cursor] ?? " "}
                </Text>
                <Text color="white">{display.slice(cursor + 1)}</Text>
              </>
            ) : (
              <Text color={isDone ? "green" : "gray"}>{display}</Text>
            )}
          </Box>
        );
      })}
    </Box>
    <Box marginTop={1}>
      <Text dimColor>[←→] move cursor  [Enter] confirm  [Esc] cancel</Text>
    </Box>
  </Box>
);
