import { Box, Button, Paper, Stack } from "@mui/material";
import type { ReactNode } from "react";
import WizardStepper from "./WizardStepper";

type WizardLayoutProps = {
  steps: string[];
  activeStep: number;
  completedSteps?: number[];
  children: ReactNode;
  onBack: () => void;
  onNext: () => void;
  backDisabled?: boolean;
  nextDisabled?: boolean;
  nextLabel?: string;
  hideBackOnFirstStep?: boolean;
};

export default function WizardLayout(props: WizardLayoutProps) {
  const {
    steps,
    activeStep,
    completedSteps,
    children,
    onBack,
    onNext,
    backDisabled,
    nextDisabled,
    nextLabel = "Dalej",
    hideBackOnFirstStep = true
  } = props;

  return (
    <Paper sx={{ mt: 3, p: 3 }}>
      <Stack spacing={3}>
        <WizardStepper steps={steps} activeStep={activeStep} completedSteps={completedSteps} />
        <Box>{children}</Box>
        <Stack direction="row" spacing={1.5} justifyContent="space-between">
          {hideBackOnFirstStep && activeStep === 0 ? <span /> : (
            <Button variant="outlined" onClick={onBack} disabled={backDisabled}>
              Wstecz
            </Button>
          )}
          <Button variant="contained" onClick={onNext} disabled={nextDisabled}>
            {nextLabel}
          </Button>
        </Stack>
      </Stack>
    </Paper>
  );
}
