import { forwardRef, JSXElementConstructor, ReactElement, Ref } from 'react';

import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import Slide from '@mui/material/Slide';
import { TransitionProps } from '@mui/material/transitions';

const Transition = forwardRef(function Transition(
    props: TransitionProps & {
        children: ReactElement<unknown, string | JSXElementConstructor<unknown>>;
        },
    ref: Ref<unknown>,
) {
    return <Slide direction="down" ref={ref} {...props} />;
});

export type DeleteProps = {
    name?: string;
    open: boolean;
    onClose: () => void;
    onDelete: () => void;
}

const Delete = (props: DeleteProps) => {
    const { name, open, onClose, onDelete } = props;

    return (
        <Dialog
            open={open}
            TransitionComponent={Transition}
            keepMounted
            onClose={onClose}
        >
            <DialogTitle>Delete {name}?</DialogTitle>
            <DialogContent>
                <DialogContentText>
                    Are you sure you want to delete this credential? This cannot be undone and will
                    require you to have the issuer reissue the credential if you need it again.
                </DialogContentText>
            </DialogContent>
            <DialogActions>
                <Button onClick={onClose} variant="outlined" color="primary">Keep</Button>
                <Button onClick={onDelete} variant="contained" color="error">Delete</Button>
            </DialogActions>
        </Dialog>
    );
};

export default Delete;
