import { Step, StepLabel, Stepper } from "@mui/material";

type WizardStepperProps = {
  steps: string[];
  activeStep: number;
  completedSteps?: number[];
};

export default function WizardStepper({ steps, activeStep, completedSteps = [] }: WizardStepperProps) {
  const completedSet = new Set(completedSteps);
  return (
    <Stepper activeStep={activeStep} alternativeLabel>
      {steps.map((label, idx) => (
        <Step key={label} completed={completedSet.has(idx) ? true : undefined}>
          <StepLabel>{label}</StepLabel>
        </Step>
      ))}
    </Stepper>
  );
}
