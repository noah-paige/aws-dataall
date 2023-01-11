import React, { useEffect, useState } from 'react';
import { DataGrid } from '@mui/x-data-grid';
import { Box, Card, CircularProgress } from '@mui/material';
import { useSnackbar } from 'notistack';
import { SyncAlt } from '@mui/icons-material';
import { LoadingButton } from '@mui/lab';
import * as PropTypes from 'prop-types';
import { SET_ERROR } from '../../store/errorReducer';
import { useDispatch } from '../../store';
import useClient from '../../hooks/useClient';
import listDatasetTableColumns from '../../api/DatasetTable/listDatasetTableColumns';
import updateColumnDescription from '../../api/DatasetTable/updateDatasetTableColumn';
import TableColumnLFTagForm from './TableColumnLFTagForm';
import syncDatasetTableColumns from '../../api/DatasetTable/syncDatasetTableColumns';
import * as Defaults from '../../components/defaults';

const TableColumns = (props) => {
  const { table, isAdmin } = props;
  const dispatch = useDispatch();
  const client = useClient();
  const { enqueueSnackbar } = useSnackbar();
  const [loading, setLoading] = useState(true);
  const [columns, setColumns] = useState(null);
  const [columnToEdit, setColumnToEdit] = useState(null);
  const [refreshingColumns, setRefreshingColumns] = useState(false);
  const [isAddLFTagModalOpen, setIsAddLFTagModalOpen] = useState(false);
  const handleAddLFTagModalOpen = () => {
    setIsAddLFTagModalOpen(true);
  };
  const handleAddLFTagModalClose = () => {
    setIsAddLFTagModalOpen(false);
  };

  const updateDescription = async (column, description) => {
    const response = await client.mutate(
      updateColumnDescription({ columnUri: column.id, input: { description } })
    );
    try {
      if (!response.errors) {
        enqueueSnackbar(`Column ${column.name} description updated`, {
          anchorOrigin: {
            horizontal: 'right',
            vertical: 'top'
          },
          variant: 'success'
        });
      } else {
        dispatch({ type: SET_ERROR, error: response.errors[0].message });
      }
    } catch (e) {
      dispatch({ type: SET_ERROR, error: e.message });
    }
  };

  const handleEditCellChangeCommitted = (e:GridCellEditCommitParams) => {
    const data = e.value;
    if (e.field === 'description') {
      columns.map((c) => {
        if (c.id === e.id && data.toString() !== c.description) {
          c.description = data.toString();
          return updateDescription(c, data.toString()).catch((e) =>
            dispatch({ type: SET_ERROR, error: e.message })
          );
        }
        return true;
      });
    }
  };

  const handleCellClick = (e) => {
    if (e.field === 'lftags' && isAdmin) {
      columns.map((c) => {
        if (c.id === e.id) {
          setColumnToEdit(c)
          handleAddLFTagModalOpen()
        }
      });
    }
  };

  const startSyncColumns = async () => {
    try {
      setRefreshingColumns(true);
      const response = await client.mutate(
        syncDatasetTableColumns(table.tableUri)
      );
      if (!response.errors) {
        setColumns(
          response.data.syncDatasetTableColumns.nodes.map((c) => ({
            id: c.columnUri,
            name:
              c.columnType && c.columnType !== 'column'
                ? `${c.name} (${c.columnType})`
                : c.name,
            type: c.typeName,
            description: c.description,
            lfTagKey: c.lfTagKey,
            lfTagValue: c.lfTagValue,
            lftags: 
              c.lfTagKey && c.lfTagKey.length > 0 
              ? c.lfTagKey.map((key,idx) => `${key}=${c.lfTagValue[idx]}`)
              : '-'
          }))
        );
        enqueueSnackbar('Columns synchronized successfully', {
          anchorOrigin: {
            horizontal: 'right',
            vertical: 'top'
          },
          variant: 'success'
        });
      } else {
        dispatch({ type: SET_ERROR, error: response.errors[0].message });
      }
    } catch (e) {
      dispatch({ type: SET_ERROR, error: e.message });
    } finally {
      setRefreshingColumns(false);
    }
  };

  const fetchItems = async () => {
    setLoading(true);
    const response = await client.query(
      listDatasetTableColumns({
        tableUri: table.tableUri,
        filter: Defaults.SelectListFilter
      })
    );
    if (!response.errors) {
      setColumns(
        response.data.listDatasetTableColumns.nodes.map((c) => ({
          id: c.columnUri,
          name:
            c.columnType && c.columnType !== 'column'
              ? `${c.name} (${c.columnType})`
              : c.name,
          type: c.typeName,
          description: c.description,
          lfTagKey: c.lfTagKey,
          lfTagValue: c.lfTagValue,
          lftags: 
          c.lfTagKey && c.lfTagKey.length > 0  
            ? c.lfTagKey.map((key,idx) => `${key}=${c.lfTagValue[idx]}`)
            : '-'
        }))
      );
    } else {
      dispatch({ type: SET_ERROR, error: response.errors[0].message });
    }
    setLoading(false);
  };

  useEffect(() => {
    if (client) {
      fetchItems().catch((e) =>
        dispatch({ type: SET_ERROR, error: e.message })
      );
    }
  }, [client, dispatch, table.tableUri]);

  if (loading) {
    return <CircularProgress />;
  }
  if (!columns) {
    return null;
  }
  const header = [
    { field: 'name', headerName: 'Name', width: 400, editable: false },
    { field: 'type', headerName: 'Type', width: 400, editable: false },
    { field: 'description', headerName: 'Description', width: 400, editable: isAdmin },
    { field: 'lftags', headerName: 'LF-Tags', width: 300, editable: false }
  ];

  return (
    <Box>
      {isAdmin && (
        <Box
          sx={{
            display: 'flex',
            flex: 1,
            justifyContent: 'flex-end',
            mb: 2
          }}
        >
          <LoadingButton
            loading={refreshingColumns}
            color="primary"
            onClick={startSyncColumns}
            startIcon={<SyncAlt fontSize="small" />}
            sx={{ m: 1 }}
            variant="outlined"
          >
            Synchronize
          </LoadingButton>
        </Box>
      )}
      <Card sx={{ height: 800, width: '100%' }}>
        {columns.length > 0 && (
          <DataGrid
            rows={columns}
            columns={header}
            onCellEditCommit={handleEditCellChangeCommitted}
            onCellClick={handleCellClick}
          />
        )}
        {isAddLFTagModalOpen && (
          <TableColumnLFTagForm
            open
            reloadColumns={fetchItems}
            columnToEdit={columnToEdit}
            onClose={handleAddLFTagModalClose}
          />
        )}
      </Card>
    </Box>
  );
};
TableColumns.propTypes = {
  table: PropTypes.object.isRequired,
  isAdmin: PropTypes.bool.isRequired
};
export default TableColumns;
